;;; Directory Local Variables
;;; For more information see (info "(emacs) Directory Variables")

((c-mode
  (eval . (setq-local flycheck-clang-include-path
                      (list (expand-file-name "libstrophe" (projectile-project-root))
                            (expand-file-name "json-c" (projectile-project-root)))))
  (eval . (setq-local company-clang-arguments
                      (list (concat "-I" (expand-file-name "libstrophe" (projectile-project-root)))
                            (concat "-I" (expand-file-name "json-c" (projectile-project-root))))))
  (eval . (setq-local tags-table-list (expand-file-name ".git/tags" (projectile-project-root))))
  (eval . (setq-local gud-gdb-command-name
                      (string-join `("gdb"
                                     "-ex 'handle SIGPIPE nostop noprint pass'"
                                     ,(concat "--args weechat -a -P 'alias,buflist,exec,irc' -r '/plugin load "
                                              (expand-file-name "xmpp.so" (projectile-project-root))
                                             "'; /debug tags"))
                                   " ")))
  (flycheck-clang-warnings . ("all" "extra" "error-implicit-function-declaration" "no-missing-field-initializers"))
  (flycheck-clang-language-standard . "gnu99")
  (flycheck-checker . c/c++-clang)
  (projectile-project-compilation-cmd . "scan-build-3.8 make -j8")))
