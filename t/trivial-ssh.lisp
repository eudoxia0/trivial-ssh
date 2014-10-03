(in-package :cl-user)
(defpackage trivial-ssh-test
  (:use :cl :fiveam))
(in-package :trivial-ssh-test)

(defparameter +system-pathname+
  (asdf:component-pathname (asdf:find-system :trivial-ssh)))

(defparameter +host+ "192.168.123.123")

(defun execute-in-directory (cmd)
  (uiop:run-program
   (format nil "cd ~S; ~A" (namestring +system-pathname+) cmd)))

(def-suite trivial-ssh)
(in-suite trivial-ssh)

(test start-vagrant
  (finishes (execute-in-directory "vagrant up")))

(test hosts-db
  (is (equal (trivial-ssh:hosts-db "known_hosts")
             (merge-pathnames
              #p".ssh/known_hosts"
              (user-homedir-pathname)))))

(test simple-connection
  (is-true
    (trivial-ssh:with-connection
        (c +host+ (trivial-ssh:pass "vagrant" "vagrant"))
      t)))

(test (stop-vagrant :depends-on start-vagrant)
  (finishes (execute-in-directory "vagrant halt")))

(run! 'trivial-ssh)
