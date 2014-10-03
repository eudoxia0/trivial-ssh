(defsystem trivial-ssh
  :version "0.1"
  :author "Fernando Borretti"
  :license "MIT"
  :depends-on (:libssh2
               :cl-fad)
  :components ((:module "src"
                :components
                ((:file "trivial-ssh"))))
  :description "An abstraction layer over cl-libssh2."
  :long-description
  #.(uiop:read-file-string
     (uiop:subpathname *load-pathname* "README.md"))
  :in-order-to ((test-op (test-op trivial-ssh-test))))
