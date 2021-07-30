;;; Directory Local Variables
;;; For more information see (info "(emacs) Directory Variables")

((c-mode
  (eval . (setq-local gud-gdb-command-name
                      (string-join `("gdb"
                                     "-ex 'handle SIGPIPE nostop noprint pass'"
                                     ,(concat "--args weechat -a -P 'alias,buflist,exec,irc' -r '/plugin load "
                                              (expand-file-name "xmpp.so" (projectile-project-root))
                                              "'"))
                                   " ")))
  (flycheck-clang-warnings . ("all" "extra" "error-implicit-function-declaration" "no-missing-field-initializers"))
  (flycheck-clang-language-standard . "c++17")
  (flycheck-checker . c/c++-clang)
  (projectile-project-compilation-cmd . "make && (make test || true)")))
