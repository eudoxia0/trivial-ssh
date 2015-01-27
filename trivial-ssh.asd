(defsystem trivial-ssh
  :author "Fernando Borretti <eudoxiahp@gmail.com>"
  :maintainer "Fernando Borretti <eudoxiahp@gmail.com>"
  :license "MIT"
  :version "0.1"
  :homepage "https://github.com/eudoxia0/trivial-ssh"
  :bug-tracker "https://github.com/eudoxia0/trivial-ssh/issues"
  :source-control (:git "git@github.com:eudoxia0/trivial-ssh.git")
  :depends-on (:trivial-ssh-libssh2)
  :components ((:module "src"
                :components
                ((:file "trivial-ssh"))))
  :description "An abstraction layer over cl-libssh2."
  :long-description
  #.(uiop:read-file-string
     (uiop:subpathname *load-pathname* "README.md"))
  :in-order-to ((test-op (test-op trivial-ssh-test))))
