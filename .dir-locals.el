;;; Directory Local Variables
;;; For more information see (info "(emacs) Directory Variables")

((nil
  (eval . (setq-local gud-gdb-command-name
                      (string-join `("gdb" "-i=mi"
                                     "-ex 'handle SIGPIPE nostop noprint pass'"
                                     ,(concat "--args weechat -a -P 'alias,buflist,exec,irc' -r '/plugin load "
                                              (expand-file-name "xmpp.so" (projectile-project-root))
                                              "'; /debug tags"))
                                   " "))))
 (c++-mode
  (eval . (setq-local flycheck-clang-include-path
                      (list (expand-file-name "libstrophe" (projectile-project-root))
                            (expand-file-name "json-c" (projectile-project-root))
                            (string-trim-right
                             (substring
                              (shell-command-to-string "xml2-config --cflags") 2))
                            (string-trim-right
                             (substring
                              (shell-command-to-string "pkg-config --cflags libsignal-protocol-c") 2))
                            "/usr/include/libxml2/" "/usr/include/signal"
                            (expand-file-name "deps/fmt/include" (projectile-project-root))
                            (expand-file-name "deps/optional/include" (projectile-project-root))
                            (expand-file-name "deps/range-v3/include" (projectile-project-root)))))
  (eval . (setq-local company-clang-arguments
                      (list (concat "-I" (expand-file-name "libstrophe" (projectile-project-root)))
                            (concat "-I" (expand-file-name "json-c" (projectile-project-root))))))
  (eval . (setq-local tags-table-list (expand-file-name ".git/tags" (projectile-project-root))))
  (flycheck-clang-warnings . ("all" "extra" "error-implicit-function-declaration" "no-missing-field-initializers"))
  (flycheck-clang-language-standard . "c++20")
  ;(flycheck-checker . c/c++-clang)
  (flycheck-checker . lsp)
  (projectile-project-compilation-cmd . "bear -- make -j8")))
