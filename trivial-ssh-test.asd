(in-package :cl-user)
(defpackage trivial-ssh-test-asd
  (:use :cl :asdf))
(in-package :trivial-ssh-test-asd)

(defsystem trivial-ssh-test
  :author "Fernando Borretti"
  :license "MIT"
  :depends-on (:trivial-ssh
               :fiveam)
  :components ((:module "t"
                :components
                ((:file "trivial-ssh")))))
