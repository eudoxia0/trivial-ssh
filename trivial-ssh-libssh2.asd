;; -*- mode: lisp; tab-width: 4; ident-tabs-mode: nil -*-

(in-package :asdf)

(cl:eval-when (:load-toplevel :execute)
  (asdf:operate 'asdf:load-op 'cffi-grovel))

(defsystem trivial-ssh-libssh2
  :description "Trivial libssh2 bindings"
  :version      "0.1"
  :author       "Oleksii Shevchuk <alxchk@gmail.com>"
  :license      "Public Domain"
  :depends-on   (#:cffi #:usocket #:cl-fad
                 #:trivial-gray-streams #:babel
                 #:split-sequence)
  :serial       t
  :components   ((:module "libssh2"
                  :serial t
                  :components
                  ((:file "package")
                   (:file "types")
                   (cffi-grovel:grovel-file "libssh2-libc-cffi")
                   (:file "util")
                   (:file "libssh2-cffi")
                   (:file "streams")
                   (:file "solutions")))))
