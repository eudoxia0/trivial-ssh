(eval-when (:load-toplevel :execute)
  (asdf:load-system :cffi-grovel))

(defsystem trivial-ssh-libssh2
  :author "Oleksii Shevchuk <alxchk@gmail.com>"
  :maintainer "Fernando Borretti <eudoxiahp@gmail.com>"
  :license "Public Domain"
  :version "0.1"
  :depends-on (:cffi
               :usocket
               :cl-fad
               :trivial-gray-streams
               :babel
               :split-sequence)
  :defsystem-depends-on (:cffi-grovel)
  :description "Trivial libssh2 bindings"
  :components ((:module "libssh2"
                :serial t
                :components
                ((:file "package")
                 (:file "types")
                 (cffi-grovel:grovel-file "libssh2-libc-cffi")
                 (:file "util")
                 (:file "libssh2-cffi")
                 (:file "streams")
                 (:file "solutions")))))
