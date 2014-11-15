;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; The beginnings of pcap analysis code
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :c-struct))

(defpackage pcap
  (:use :cl :c-struct)
  (:export :pcap-hdr :pcap-rec :def-pcap-struct
	   :ethernet
	   :open-pcap :close-pcap :read-pcap :with-pcap))

(in-package :pcap)
(provide :pcap)

;; Define a limitied number of link constants
(defconstant linktype_null 0)
(defconstant linktype_ethernet 1)
(defconstant linktype_raw 101)

;; Constants to determine the pcap header/record byte ordering. 
(defconstant pcap-magic
  '((#xa1b2c3d4 :big-endian :micro)
    (#xd4d3b2a1 :little-endian :micro)
    (#xa1b23c4d :big-endian :nano)
    (#x4d3cb2a1 :little-endian :nano)))

(defvar *max-snaplen* 16000
  "Default limit for maximum payload size")

(defvar *root* (make-hash-table)
  "Links between payload analysis objects")


;; Structures for pcaps
(def-c-struct pcap-hdr
  (major uint16)
  (minor uint16)
  (thiszone uint32)
  (sigfigs uint32)
  (snaplen uint32)
  (network uint32)
  ;; control data
  filename
  handle
  octet-order)

(def-c-struct pcap-rec
  (ts-sec uint32)
  (ts-xsec uint32)
  (incl-len uint32)
  (orig-len uint32)
  data ;; raw payload data
  tree) ;; breakdown 


(defmacro def-pcap-struct (name struct-list &rest body)
  "Define a c-struct for some network element, it's relationship to others."

  (labels ((make-link (tag key value)
	     `(setf (gethash ',tag *root*)
		    (acons ,key ',value (gethash ',tag *root*))))

	   (link-expr (dst expr)
	     (when (symbolp expr)
	       (setf expr `(pcap-hdr (eql network ,expr))))
	     (make-link (first expr)
			#'(lambda (object) (with-slots ((get (frst dst) :slots)) object
					     (second expr)))
			dst)))

    (let ((link (cdr (find-if (lambda (x) (and (consp x) (eq (first x) :link)))
			      body)))
	  (method (cdr (find-if (lambda (x) (and (consp x) (eq (first x) :method)))
				body))))

      `(progn
	 (def-c-struct ,name ,@struct-list)
	 ,@(mapcar (lambda (x) (link-expr name x)) link)
	 ,(when method
		`(defmethod read-object :after ((,(caar method) ,name) ,(second (first method)) &key)
		   ,@(rest method)))))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; structures - ETHERNET
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(def-pcap-struct ethernet
    ((mac-src (uint8 :size 6))
     (mac-dst (uint8 :size 6))
     vlan-tag
     ethertype)

  (:link linktype-ethernet)

  (:method (object stream)
    (with-slots (vlan-tag ethertype) object
      (when (eql #x8011 (setf ethertype (read-value 'uint16 stream)))
	(error "vlan tagging unsupported"))
      (setf vlan-tag 0))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; IPv4
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(def-pcap-struct ipv4
    ((version% uint8)
     (version (bit :from version% :spec (byte 4 4)))
     (hdr-len (bit :from version% :spec (byte 4 0)))
     (dspc uint8)
     (total-len uint16)
     (ident uint16)
     (fragment uint16)
     (ttl uint8)
     (protocol uint8)
     (checksum uint16)
     (src-ip (uint8 :size 4))
     (dst-ip (uint8 :size 4)))

  (:link (ethernet (eql #x0800 ethertype))))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; pcap access functions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defun open-pcap (file &key (max-snaplen *max-snaplen*))
  "Open a pcap file for input"
  (let* ((file-handle (open file :direction :input
			    :element-type 'uint8
			    :if-does-not-exists :error))

	 ;; Determine endian order of headers by an initial read as big-endian
	 (magic (or (assoc (read-value 'uint32 file-handle :octet-order :big-endian)
			   pcap-magic)
		    (error "Couldn't match magic numbers - is it pcap?")))

	 (*octet-order* (second magic))

	 (pcap-hdr (read-value 'pcap-hdr file-handle)))

    (with-slots (major minor filename handle octet-order snaplen) pcap-hdr
      (unless (and (= major 2) (= minor 4))
	      (error "Not a 2.4 pcap file, sorry"))
      (setf filename file
	    handle file-handle
	    octet-order *octet-order*
	    snaplen (min max-snaplen snaplen))
      pcap-hdr)))
			 

(defun close-pcap (pcap)
  (close (slot-value pcap 'handle)))


(defun read-pcap (pcap &optional (eof-error-p t))
  "Read the next pcap record. On eof, raises the condition unless eof-error-p is t. 
Actual data length is limited to the max-snaplen defined when open-pcap called. Octet
swapping is set via *octet-order* for the scope of read-pcap"

  (labels ((find-link-expr (obj)
	     ;; evaluate expression associated with object key, returning the
	     ;; associated tag
	     (cdr (assoc-if (lambda (x) (funcall x obj))
			    (gethash (type-of obj) *root*))))


	   (apply-expr (obj stream &optional acc)
	     ;; Construct analysis objects from the stream content until none remain
	     (let ((tag (find-link-expr obj)))
	       (if tag
		   (let ((next (read-value tag stream)))
		     (apply-expr next stream (cons next acc)))
		   (nreverse acc)))))
		 

    (handler-bind
	;; 
	((end-of-file (lambda (c)
			(declare (ignorable c))
			(unless eof-error-p (return-from read-pcap nil)))))

      ;;
      (with-slots (handle octet-order snaplen) pcap
	(let* ((*octet-order* octet-order)
	       (rec (read-value 'pcap-rec handle))
	       (to-read (min snaplen (slot-value rec 'incl-len))))

	  (setf (slot-value rec 'data)
		(read-value 'uint8 handle :size to-read))

	  (unless (= (slot-value rec 'incl-len)
		     to-read)
	    (stream-position handle (+ (stream-position handle)
				       (- (slot-value rec 'incl-len) to-read)))
	    (setf (slot-value rec 'incl-len) to-read))

	  ;; Analyse payload with octet order :big-endian to match the network byte order
	  ;; of the data
	  (let ((*octet-order* :big-endian))
	    (setf (slot-value rec 'tree)
		  (apply-expr pcap (make-octet-stream (slot-value rec 'data)))))

	  rec)))))


(defmacro with-pcap ((sym filename) &body body)
  "Open a pcap file, read all records with SYM bound to an instance
of PCAP-REC"

  (let ((handle (gensym)))
    `(let ((,handle (pcap::open-pcap ,filename)))
       (unwind-protect
	    (do ((,sym (pcap::read-pcap ,handle nil)
		       (pcap::read-pcap ,handle nil)))

		((null ,sym))
	      
	      ,@body)

	 (pcap::pcap-close ,handle)))))