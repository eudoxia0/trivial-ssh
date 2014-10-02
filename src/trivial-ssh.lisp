(in-package :cl-user)
(defpackage trivial-ssh
  (:use :cl)
  (:export :hosts-db))
(in-package :trivial-ssh)

;;; Hosts database

(defun hosts-db (name)
  "Path of the hosts database."
  (merge-pathnames
   (make-pathname :directory (list :relative ".ssh")
                  :name name)
   (user-homedir-pathname)))

(defparameter +default-hosts-db+ (hosts-db "trivial_ssh_hosts"))

;; Ensure hosts database exists
(unless (probe-file +default-hosts-db+)
  (with-open-file (file +default-hosts-db+ :if-does-not-exist :create)))
