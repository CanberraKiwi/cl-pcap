;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; c-struct package provides an interface to work with external data sources using more natural
;; data structures than simple octets - based on the excellent examples in Pete Sebel's Gigamonkeys
;; book (http://www.gigamonkeys.com/book/). 
;;
;; This code has only been tested with SBCL ....
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defpackage c-struct
  (:use :cl)
  (:export *octet-order* :endian
	   :uint8 :uint16 :uint32
	   :read-value :read-object
	   :read-octet :read-n-octets :stream-position
	   :def-c-struct :make-octet-stream))

(provide :c-struct)
(in-package :c-struct)

;; Define endian as a type to facilitate handling of endian-ness. 
(deftype endian () '(member :big-endian         ;; lowest address is most significant (like arabic numbers)
		            :little-endian))    ;; lowest address is least significant


;; Define shorthand names from common types using familiar C names
(deftype uint8  () '(unsigned-byte 8))
(deftype uint16 () '(unsigned-byte 16))
(deftype uint32 () '(unsigned-byte 32))


;; Special var controls reading of multi-octet values on a global basis. This defines
;; the external octet order
(defvar *octet-order* :big-endian
  "External octet order")


;; Utility functions - not exported
(defun mklist (arg)
  (if (consp arg) 
      arg
      (list arg)))

(defun as-keyword (arg) 
  (intern (string arg) :keyword))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Stream abstraction defined here wraps an octet array to provide, albeit in a simple way, the 
;; functionality of with-input-from-string
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defclass octet-array-stream ()
  ((source :initarg :source :type (array uint8 *))
   (start  :initform 0 :initarg :start :type fixnum)
   (end    :initform 0 :initarg :end   :type fixnum)))


(defun make-octet-stream (array &key (start 0) (end (array-dimension array 0)))
  "Wrap an octet array to make it readable as a stream"
  (make-instance 'octet-array-stream :source array :start start :end end))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Generic methods for reading files and octet streams
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defgeneric read-octet (stream)
  (:documentation "Read a single octet")
  
  (:method ((stream stream))
    (read-byte stream))

  (:method ((stream octet-array-stream))
    (with-slots (source start end) stream
      (when (>= start end) (error 'end-of-file))
      (prog1
	  (aref source start)
	(incf start)))))


(defgeneric read-n-octets (stream buffer &optional buffer-start buffer-end)
  (:documentation "Read n bytes into a supplied buffer")

  (:method ((stream stream) buffer &optional (buffer-start 0) (buffer-size (array-dimension buffer 0)))
    (sb-sys:read-n-bytes stream buffer buffer-start buffer-size))

  (:method ((stream octet-array-stream) buffer &optional (buffer-start 0) (buffer-size (array-dimension buffer 0)))
    (with-slots (source start end) stream
      (when (>= start end) (error 'end-of-file))
      (prog1
	  (replace buffer source :start1 buffer-start
		                 :end1  (+ buffer-start buffer-size)
				 :start2 start)
	(incf start buffer-size)))))


(defgeneric stream-position (stream &optional delta)
  (:documentation "Report current stream position or move to a new position")

  (:method ((stream stream) &optional delta)
    (file-position delta))

  (:method ((stream octet-array-stream) &optional delta)
    (with-slots (start) stream
      (if (null delta)
	  start
	  (setf start delta)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Generic methods to read values from streams. Handles octet swapping for multi-octet values.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defgeneric read-value (type stream &key)
  (:documentation "Read a value from an octet stream (for the initial defined types), external
octet order is defined by *octet-order* or keyword. Reading multiple octets from an octet-array
uses a displaced array to reduce allocation overhead.")

  (:method ((type (eql 'uint8)) stream &key (size 1))
    (if (= size 1)
	(read-octet stream)
	(typecase stream
	  (stream 
	   (let ((buffer (make-array size :element-type 'uint8)))
	     (read-n-octets stream buffer 0 size)))

	  (octet-array-stream
	   (with-slots (source start) stream
	     (let ((buffer (make-array size :element-type 'uint8
				            :displaced-to source
					    :displaced-index-offset start)))
	       (incf start size)
	       buffer))))))


  (:method ((type (eql 'uint16)) stream &key (octet-order *octet-order*))
    (if (eq octet-order :little-endian)
	(logior (read-octet stream)
		(ash (read-octet stream) 8))

	(logior (ash (read-octet stream) 8)
		(read-octet stream))))


  (:method ((type (eql 'uint32)) stream &key (octet-order *octet-order*))
    (if (eq octet-order :little-endian)

	(logior (read-octet stream)
		(ash (read-octet stream) 8)
		(ash (read-octet stream) 16)
		(ash (read-octet stream) 24))

	(logior (ash (read-octet stream) 24)
		(ash (read-octet stream) 16)
		(ash (read-octet stream) 8)
		(read-octet stream))))


  (:method ((type (eql 'bit)) stream &key from spec)
    ;; The pseudo-type 'bit allows a bit field to be extracted from an earlier field in a c-struct
    (ldb spec from)))




(defgeneric read-object (object stream &key)
  (:documentation "C-struct objects read values from streams via this function called from
read-value. Standard CLOS method combination can be used to customise this process"))


(defmacro def-c-struct(name &body spec)
  "Define a c-like structure"
  ;; Note the use of flet to define local functions. This is slightly more cumbersome during
  ;; testing, but makes the scope of function usage clear during later life

  (flet ((slot->defclass-slot (spec)
	   (let ((name (first (mklist spec))))
	     `(,name :initarg ,(as-keyword name) :accessor ,name)))

	 (slot->read-value (spec stream)
	   (destructuring-bind (name (type &rest args)) (list (first spec) (mklist (second spec)))
	     `(setf ,name (read-value ',type ,stream ,@args)))))

    (let ((stream (gensym))
	  (object (gensym))
	  (read-spec (remove-if #'symbolp spec)))

      `(progn
	 ;; class definition
	 (defclass ,name ()
	   ,(mapcar #'slot->defclass-slot spec))

	 ;; read-object into an existing object instance
	 (defmethod read-object ((exist-obj ,name) ,stream &key)
	   (with-slots ,(mapcar #'first read-spec) exist-obj
	     ,@(mapcar #'(lambda (x) (slot->read-value x stream)) read-spec)
	     exist-obj))

	 ;; Create a new instance and read into it
	 (defmethod read-value ((type (eql ',name)) ,stream &key)
	   (let ((,object (make-instance ',name)))
	     (read-object ,object ,stream)))

	 ;; Subsequent macros that work on classes need access to the slot names. Pete Sebel
	 ;; uses this for handling inheritance. Later on I use it to use with-slots in a generic
	 ;; manner.
	 (eval-when (:compile-toplevel :load-toplevel :execute)
	   (setf (get ',name :slots)
		 ',(mapcar #'(lambda (x) (first (mklist x))) spec)))))))
