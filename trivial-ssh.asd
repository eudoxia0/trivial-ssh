(defsystem trivial-ssh
  :version "0.1"
  :author "Fernando Borretti"
  :license "MIT"
  :homepage "https://github.com/eudoxia0/trivial-ssh"
  :depends-on (:trivial-ssh-libssh2)
  :components ((:module "src"
                :components
                ((:file "trivial-ssh"))))
  :description "An abstraction layer over cl-libssh2."
  :long-description
  #.(uiop:read-file-string
     (uiop:subpathname *load-pathname* "README.md"))
  :in-order-to ((test-op (test-op trivial-ssh-test))))
