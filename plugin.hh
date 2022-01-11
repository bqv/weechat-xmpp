// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <functional>
#include <optional>
#include <type_traits>
#include <cstring>
#include <stdexcept>

#include "weechat.hh"
#include "config.hh"

template<typename Or_Input,
         typename Func,
         typename Input_Type = typename Or_Input::value_type,
         typename Or_Output = std::invoke_result_t<Func, Input_Type>>
constexpr Or_Output operator>>= (Or_Input input, Func f) {
    static_assert(std::is_invocable_v<decltype(f), Input_Type>,
                  "The function passed in must take type "
                  "(Or_Input::value_type) as its argument");

    return input ? std::invoke(f, *input) : std::nullopt;
}

namespace weechat {
    class plugin : public std::reference_wrapper<struct t_weechat_plugin> {
    public:
        plugin();
        explicit plugin(struct t_weechat_plugin* plugin);

        bool init(std::vector<std::string> args);
        bool end();
        std::string_view name() const;
        weechat::xmpp::config& config();

        inline operator struct t_weechat_plugin* () const { return &this->get(); }
        inline struct t_weechat_plugin* operator-> () const { return &this->get(); }
        inline plugin& operator= (struct t_weechat_plugin* plugin_ptr) {
            std::reference_wrapper<struct t_weechat_plugin>::operator=(*plugin_ptr);
            return *this;
        }

        static constexpr const double timer_interval_sec = 0.01;

    private:
        std::optional<hook> m_process_timer;
        std::optional<gui_bar_item> m_typing_bar_item;
        std::optional<weechat::xmpp::config> m_config;
    };

    namespace globals {
        extern weechat::plugin plugin;
    }

    inline const char *plugin_get_name(struct t_weechat_plugin *plugin) {
        return globals::plugin->plugin_get_name(plugin);
    }

    inline void charset_set(const char *charset) {
        return globals::plugin->charset_set(globals::plugin, charset);
    }
    inline char *iconv_to_internal(const char *charset, const char *string) {
        return globals::plugin->iconv_to_internal(charset, string);
    }
    inline char *iconv_from_internal(const char *charset, const char *string) {
        return globals::plugin->iconv_from_internal(charset, string);
    }
    inline const char *gettext(const char *string) {
        return globals::plugin->gettext(string);
    }
    inline const char *ngettext(const char *single, const char *plural, int count) {
        return globals::plugin->ngettext(single, plural, count);
    }
    inline char *strndup(const char *string, int length) {
        return globals::plugin->strndup(string, length);
    }
    inline void string_tolower(char *string) {
        return globals::plugin->string_tolower(string);
    }
    inline void string_toupper(char *string) {
        return globals::plugin->string_toupper(string);
    }
    inline int strcasecmp(const char *string1, const char *string2) {
        return globals::plugin->strcasecmp(string1, string2);
    }
    inline int strcasecmp_range(const char *string1, const char *string2,
                                int range) {
        return globals::plugin->strcasecmp_range(string1, string2, range);
    }
    inline int strncasecmp(const char *string1, const char *string2, int max) {
        return globals::plugin->strncasecmp(string1, string2, max);
    }
    inline int strncasecmp_range(const char *string1, const char *string2,
                                 int max, int range) {
        return globals::plugin->strncasecmp_range(string1, string2, max, range);
    }
    inline int strcmp_ignore_chars(const char *string1, const char *string2,
                                   const char *chars_ignored, int case_sensitive) {
        return globals::plugin->strcmp_ignore_chars(string1, string2, chars_ignored, case_sensitive);
    }
    inline const char *strcasestr(const char *string, const char *search) {
        return globals::plugin->strcasestr(string, search);
    }
    inline int strlen_screen(const char *string) {
        return globals::plugin->strlen_screen(string);
    }
    inline int string_match(const char *string, const char *mask,
                            int case_sensitive) {
        return globals::plugin->string_match(string, mask, case_sensitive);
    }
    inline int string_match_list(const char *string, const char **masks,
                                 int case_sensitive) {
        return globals::plugin->string_match_list(string, masks, case_sensitive);
    }
    inline char *string_replace(const char *string, const char *search,
                                const char *replace) {
        return globals::plugin->string_replace(string, search, replace);
    }
    inline char *string_expand_home(const char *path) {
        return globals::plugin->string_expand_home(path);
    }
    inline char *string_eval_path_home(const char *path,
                                       struct t_hashtable *pointers,
                                       struct t_hashtable *extra_vars,
                                       struct t_hashtable *options) {
        return globals::plugin->string_eval_path_home(path, pointers, extra_vars, options);
    }
    inline char *string_remove_quotes(const char *string, const char *quotes) {
        return globals::plugin->string_remove_quotes(string, quotes);
    }
    inline char *string_strip(const char *string, int left, int right,
                              const char *chars) {
        return globals::plugin->string_strip(string, left, right, chars);
    }
    inline char *string_convert_escaped_chars(const char *string) {
        return globals::plugin->string_convert_escaped_chars(string);
    }
    inline char *string_mask_to_regex(const char *mask) {
        return globals::plugin->string_mask_to_regex(mask);
    }
    inline const char *string_regex_flags(const char *regex, int default_flags,
                                          int *flags) {
        return globals::plugin->string_regex_flags(regex, default_flags, flags);
    }
    inline int string_regcomp(void *preg, const char *regex, int default_flags) {
        return globals::plugin->string_regcomp(preg, regex, default_flags);
    }
    inline int string_has_highlight(const char *string,
                                    const char *highlight_words) {
        return globals::plugin->string_has_highlight(string, highlight_words);
    }
    inline int string_has_highlight_regex(const char *string, const char *regex) {
        return globals::plugin->string_has_highlight_regex(string, regex);
    }
    inline char *string_replace_regex(const char *string, void *regex,
                                      const char *replace,
                                      const char reference_char,
                                      char *(*callback)(void *data,
                                                        const char *text),
                                      void *callback_data) {
        return globals::plugin->string_replace_regex(string, regex, replace, reference_char, callback, callback_data);
    }
    inline char **string_split(const char *string, const char *separators,
                               const char *strip_items, int flags,
                               int num_items_max, int *num_items) {
        return globals::plugin->string_split(string, separators, strip_items, flags, num_items_max, num_items);
    }
    inline char **string_split_shell(const char *string, int *num_items) {
        return globals::plugin->string_split_shell(string, num_items);
    }
    inline void string_free_split(char **split_string) {
        return globals::plugin->string_free_split(split_string);
    }
    inline char *string_build_with_split_string(const char **split_string,
                                                const char *separator) {
        return globals::plugin->string_build_with_split_string(split_string, separator);
    }
    inline char **string_split_command(const char *command, char separator) {
        return globals::plugin->string_split_command(command, separator);
    }
    inline void string_free_split_command(char **split_command) {
        return globals::plugin->string_free_split_command(split_command);
    }
    inline char *string_format_size(unsigned long long size) {
        return globals::plugin->string_format_size(size);
    }
    inline int string_color_code_size(const char *string) {
        return globals::plugin->string_color_code_size(string);
    }
    inline char *string_remove_color(const char *string, const char *replacement) {
        return globals::plugin->string_remove_color(string, replacement);
    }
    inline int string_base_encode(int base, const char *from, int length,
                                  char *to) {
        return globals::plugin->string_base_encode(base, from, length, to);
    }
    inline int string_base_decode(int base, const char *from, char *to) {
        return globals::plugin->string_base_decode(base, from, to);
    }
    inline char *string_hex_dump(const char *data, int data_size,
                                 int bytes_per_line, const char *prefix,
                                 const char *suffix) {
        return globals::plugin->string_hex_dump(data, data_size, bytes_per_line, prefix, suffix);
    }
    inline int string_is_command_char(const char *string) {
        return globals::plugin->string_is_command_char(string);
    }
    inline const char *string_input_for_buffer(const char *string) {
        return globals::plugin->string_input_for_buffer(string);
    }
    inline char *string_eval_expression(const char *expr,
                                        struct t_hashtable *pointers,
                                        struct t_hashtable *extra_vars,
                                        struct t_hashtable *options) {
        return globals::plugin->string_eval_expression(expr, pointers, extra_vars, options);
    }
    inline char **string_dyn_alloc(int size_alloc) {
        return globals::plugin->string_dyn_alloc(size_alloc);
    }
    inline int string_dyn_copy(char **string, const char *new_string) {
        return globals::plugin->string_dyn_copy(string, new_string);
    }
    inline int string_dyn_concat(char **string, const char *add, int bytes) {
        return globals::plugin->string_dyn_concat(string, add, bytes);
    }
    inline char *string_dyn_free(char **string, int free_string) {
        return globals::plugin->string_dyn_free(string, free_string);
    }

    inline int utf8_has_8bits(const char *string) {
        return globals::plugin->utf8_has_8bits(string);
    }
    inline int utf8_is_valid(const char *string, int length, char **error) {
        return globals::plugin->utf8_is_valid(string, length, error);
    }
    inline void utf8_normalize(char *string, char replacement) {
        return globals::plugin->utf8_normalize(string, replacement);
    }
    inline const char *utf8_prev_char(const char *string_start,
                                      const char *string) {
        return globals::plugin->utf8_prev_char(string_start, string);
    }
    inline const char *utf8_next_char(const char *string) {
        return globals::plugin->utf8_next_char(string);
    }
    inline int utf8_char_int(const char *string) {
        return globals::plugin->utf8_char_int(string);
    }
    inline int utf8_char_size(const char *string) {
        return globals::plugin->utf8_char_size(string);
    }
    inline int utf8_strlen(const char *string) {
        return globals::plugin->utf8_strlen(string);
    }
    inline int utf8_strnlen(const char *string, int bytes) {
        return globals::plugin->utf8_strnlen(string, bytes);
    }
    inline int utf8_strlen_screen(const char *string) {
        return globals::plugin->utf8_strlen_screen(string);
    }
    inline int utf8_charcmp(const char *string1, const char *string2) {
        return globals::plugin->utf8_charcmp(string1, string2);
    }
    inline int utf8_charcasecmp(const char *string1, const char *string2) {
        return globals::plugin->utf8_charcasecmp(string1, string2);
    }
    inline int utf8_char_size_screen(const char *string) {
        return globals::plugin->utf8_char_size_screen(string);
    }
    inline const char *utf8_add_offset(const char *string, int offset) {
        return globals::plugin->utf8_add_offset(string, offset);
    }
    inline int utf8_real_pos(const char *string, int pos) {
        return globals::plugin->utf8_real_pos(string, pos);
    }
    inline int utf8_pos(const char *string, int real_pos) {
        return globals::plugin->utf8_pos(string, real_pos);
    }
    inline char *utf8_strndup(const char *string, int length) {
        return globals::plugin->utf8_strndup(string, length);
    }

    inline int crypto_hash(const void *data, int data_size,
                           const char *hash_algo, void *hash, int *hash_size) {
        return globals::plugin->crypto_hash(data, data_size, hash_algo, hash, hash_size);
    }
    inline int crypto_hash_pbkdf2(const void *data, int data_size,
                                  const char *hash_algo,
                                  const void *salt, int salt_size,
                                  int iterations,
                                  void *hash, int *hash_size) {
        return globals::plugin->crypto_hash_pbkdf2(data, data_size, hash_algo, salt, salt_size, iterations, hash, hash_size);
    }
    inline int crypto_hmac(const void *key, int key_size,
                           const void *message, int message_size,
                           const char *hash_algo, void *hash, int *hash_size) {
        return globals::plugin->crypto_hmac(key, key_size, message, message_size, hash_algo, hash, hash_size);
    }

    inline int mkdir_home(const char *directory, int mode) {
        return globals::plugin->mkdir_home(directory, mode);
    }
    inline int mkdir(const char *directory, int mode) {
        return globals::plugin->mkdir(directory, mode);
    }
    inline int mkdir_parents(const char *directory, int mode) {
        return globals::plugin->mkdir_parents(directory, mode);
    }
    inline void exec_on_files(const char *directory, int recurse_subdirs,
                              int hidden_files,
                              void (*callback)(void *data, const char *filename),
                              void *callback_data) {
        return globals::plugin->exec_on_files(directory, recurse_subdirs, hidden_files, callback, callback_data);
    }
    inline char *file_get_content(const char *filename) {
        return globals::plugin->file_get_content(filename);
    }

    inline int util_timeval_cmp(struct timeval *tv1, struct timeval *tv2) {
        return globals::plugin->util_timeval_cmp(tv1, tv2);
    }
    inline long long util_timeval_diff(struct timeval *tv1, struct timeval *tv2) {
        return globals::plugin->util_timeval_diff(tv1, tv2);
    }
    inline void util_timeval_add(struct timeval *tv, long long interval) {
        return globals::plugin->util_timeval_add(tv, interval);
    }
    inline const char *util_get_time_string(const time_t *date) {
        return globals::plugin->util_get_time_string(date);
    }
    inline int util_version_number(const char *version) {
        return globals::plugin->util_version_number(version);
    }

    inline struct t_weelist *list_new() {
        return globals::plugin->list_new();
    }
    inline struct t_weelist_item *list_add(struct t_weelist *weelist,
                                           const char *data,
                                           const char *where,
                                           void *user_data) {
        return globals::plugin->list_add(weelist, data, where, user_data);
    }
    inline struct t_weelist_item *list_search(struct t_weelist *weelist,
                                              const char *data) {
        return globals::plugin->list_search(weelist, data);
    }
    inline int list_search_pos(struct t_weelist *weelist,
                               const char *data) {
        return globals::plugin->list_search_pos(weelist, data);
    }
    inline struct t_weelist_item *list_casesearch(struct t_weelist *weelist,
                                                  const char *data) {
        return globals::plugin->list_casesearch(weelist, data);
    }
    inline int list_casesearch_pos(struct t_weelist *weelist,
                                   const char *data) {
        return globals::plugin->list_casesearch_pos(weelist, data);
    }
    inline struct t_weelist_item *list_get(struct t_weelist *weelist,
                                           int position) {
        return globals::plugin->list_get(weelist, position);
    }
    inline void list_set(struct t_weelist_item *item, const char *value) {
        return globals::plugin->list_set(item, value);
    }
    inline struct t_weelist_item *list_next(struct t_weelist_item *item) {
        return globals::plugin->list_next(item);
    }
    inline struct t_weelist_item *list_prev(struct t_weelist_item *item) {
        return globals::plugin->list_prev(item);
    }
    inline const char *list_string(struct t_weelist_item *item) {
        return globals::plugin->list_string(item);
    }
    template<typename T>
    inline T *list_user_data(struct t_weelist_item *item) {
        return static_cast<T*>(
            globals::plugin->list_user_data(item));
    }
    inline int list_size(struct t_weelist *weelist) {
        return globals::plugin->list_size(weelist);
    }
    inline void list_remove(struct t_weelist *weelist,
                            struct t_weelist_item *item) {
        return globals::plugin->list_remove(weelist, item);
    }
    inline void list_remove_all(struct t_weelist *weelist) {
        return globals::plugin->list_remove_all(weelist);
    }
    inline void list_free(struct t_weelist *weelist) {
        return globals::plugin->list_free(weelist);
    }

    inline struct t_arraylist *arraylist_new(int initial_size,
                                             int sorted,
                                             int allow_duplicates,
                                             int (*callback_cmp)(void *data,
                                                                 struct t_arraylist *arraylist,
                                                                 void *pointer1,
                                                                 void *pointer2),
                                             void *callback_cmp_data,
                                             void (*callback_free)(void *data,
                                                                   struct t_arraylist *arraylist,
                                                                   void *pointer),
                                             void *callback_free_data) {
        return globals::plugin->arraylist_new(initial_size, sorted, allow_duplicates, callback_cmp, callback_cmp_data, callback_free, callback_free_data);
    }
    inline int arraylist_size(struct t_arraylist *arraylist) {
        return globals::plugin->arraylist_size(arraylist);
    }
    template<typename T>
    inline T *arraylist_get(struct t_arraylist *arraylist, int index) {
        return static_cast<T>(
            globals::plugin->arraylist_get(arraylist, index));
    }
    template<typename T>
    inline T *arraylist_search(struct t_arraylist *arraylist, void *pointer,
                                  int *index, int *index_insert) {
        return static_cast<T>(
            globals::plugin->arraylist_search(arraylist, pointer, index, index_insert));
    }
    inline int arraylist_insert(struct t_arraylist *arraylist, int index,
                                void *pointer) {
        return globals::plugin->arraylist_insert(arraylist, index, pointer);
    }
    inline int arraylist_add(struct t_arraylist *arraylist, void *pointer) {
        return globals::plugin->arraylist_add(arraylist, pointer);
    }
    inline int arraylist_remove(struct t_arraylist *arraylist, int index) {
        return globals::plugin->arraylist_remove(arraylist, index);
    }
    inline int arraylist_clear(struct t_arraylist *arraylist) {
        return globals::plugin->arraylist_clear(arraylist);
    }
    inline void arraylist_free(struct t_arraylist *arraylist) {
        return globals::plugin->arraylist_free(arraylist);
    }

    inline struct t_hashtable *hashtable_new(int size,
                                             const char *type_keys,
                                             const char *type_values,
                                             unsigned long long (*callback_hash_key)(struct t_hashtable *hashtable,
                                                                                     const void *key),
                                             int (*callback_keycmp)(struct t_hashtable *hashtable,
                                                                    const void *key1,
                                                                    const void *key2)) {
        return globals::plugin->hashtable_new(size, type_keys, type_values, callback_hash_key, callback_keycmp);
    }
    inline struct t_hashtable_item *hashtable_set_with_size(struct t_hashtable *hashtable,
                                                            const void *key,
                                                            int key_size,
                                                            const void *value,
                                                            int value_size) {
        return globals::plugin->hashtable_set_with_size(hashtable, key, key_size, value, value_size);
    }
    inline struct t_hashtable_item *hashtable_set(struct t_hashtable *hashtable,
                                                  const void *key,
                                                  const void *value) {
        return globals::plugin->hashtable_set(hashtable, key, value);
    }
    template<typename T>
    inline T *hashtable_get(struct t_hashtable *hashtable, const void *key) {
        return static_cast<T>(
            globals::plugin->hashtable_get(hashtable, key));
    }
    inline int hashtable_has_key(struct t_hashtable *hashtable, const void *key) {
        return globals::plugin->hashtable_has_key(hashtable, key);
    }
    inline void hashtable_map(struct t_hashtable *hashtable,
                              void (*callback_map) (void *data,
                                                    struct t_hashtable *hashtable,
                                                    const void *key,
                                                    const void *value),
                              void *callback_map_data) {
        return globals::plugin->hashtable_map(hashtable, callback_map, callback_map_data);
    }
    inline void hashtable_map_string(struct t_hashtable *hashtable,
                                     void (*callback_map) (void *data,
                                                           struct t_hashtable *hashtable,
                                                           const char *key,
                                                           const char *value),
                                     void *callback_map_data) {
        return globals::plugin->hashtable_map_string(hashtable, callback_map, callback_map_data);
    }
    inline struct t_hashtable *hashtable_dup(struct t_hashtable *hashtable) {
        return globals::plugin->hashtable_dup(hashtable);
    }
    inline int hashtable_get_integer(struct t_hashtable *hashtable,
                                     const char *property) {
        return globals::plugin->hashtable_get_integer(hashtable, property);
    }
    inline const char *hashtable_get_string(struct t_hashtable *hashtable,
                                            const char *property) {
        return globals::plugin->hashtable_get_string(hashtable, property);
    }
    inline void hashtable_set_pointer(struct t_hashtable *hashtable,
                                      const char *property,
                                      void *pointer) {
        return globals::plugin->hashtable_set_pointer(hashtable, property, pointer);
    }
    inline int hashtable_add_to_infolist(struct t_hashtable *hashtable,
                                         struct t_infolist_item *infolist_item,
                                         const char *prefix) {
        return globals::plugin->hashtable_add_to_infolist(hashtable, infolist_item, prefix);
    }
    inline int hashtable_add_from_infolist(struct t_hashtable *hashtable,
                                           struct t_infolist *infolist,
                                           const char *prefix) {
        return globals::plugin->hashtable_add_from_infolist(hashtable, infolist, prefix);
    }
    inline void hashtable_remove(struct t_hashtable *hashtable, const void *key) {
        return globals::plugin->hashtable_remove(hashtable, key);
    }
    inline void hashtable_remove_all(struct t_hashtable *hashtable) {
        return globals::plugin->hashtable_remove_all(hashtable);
    }
    inline void hashtable_free(struct t_hashtable *hashtable) {
        return globals::plugin->hashtable_free(hashtable);
    }

    inline struct t_config_file *config_new(const char *name,
                                            config_file::reload_callback& reload_cb) {
        return globals::plugin->config_new(
            globals::plugin, name,
            [] (const void *pointer, void *, struct t_config_file *file) {
<<<<<<< Updated upstream
                auto func = *reinterpret_cast<const config_file::reload_callback*>(pointer);
=======
                auto& func = *reinterpret_cast<const config_file::reload_callback*>(pointer);
>>>>>>> Stashed changes
                config_file file_(file);
                return func(file_);
            }, &reload_cb, nullptr);
    }
    inline struct t_config_section *config_new_section(struct t_config_file *file,
                                                       const char *name,
                                                       bool user_can_add_options,
                                                       bool user_can_delete_options,
<<<<<<< Updated upstream
                                                       config_section::read_callback& read_cb,
                                                       config_section::write_callback& write_cb,
                                                       config_section::write_default_callback& write_default_cb,
                                                       config_section::create_option_callback& create_cb,
                                                       config_section::delete_option_callback& delete_cb) {
        return globals::plugin->config_new_section(
            file, name, user_can_add_options, user_can_delete_options,
            [] (const void *pointer, void *, struct t_config_file *file,
                struct t_config_section *section, const char *key, const char *value) {
                auto func = *reinterpret_cast<const config_section::read_callback*>(pointer);
                config_file file_(file);
                config_section section_(section);
                return func(file_, section_, key, value);
            }, &read_cb, nullptr,
            [] (const void *pointer, void *, struct t_config_file *file, const char *name) {
                auto func = *reinterpret_cast<const config_section::write_callback*>(pointer);
                config_file file_(file);
                return func(file_, name);
            }, &write_cb, nullptr,
            [] (const void *pointer, void *, struct t_config_file *file, const char *name) {
                auto func = *reinterpret_cast<const config_section::write_default_callback*>(pointer);
                config_file file_(file);
                return func(file_, name);
            }, &write_default_cb, nullptr,
            [] (const void *pointer, void *, struct t_config_file *file,
                struct t_config_section *section, const char *key, const char *value) {
                auto func = *reinterpret_cast<const config_section::create_option_callback*>(pointer);
                config_file file_(file);
                config_section section_(section);
                return func(file_, section_, key, value);
            }, &create_cb, nullptr,
            [] (const void *pointer, void *, struct t_config_file *file,
                struct t_config_section *section, struct t_config_option *option) {
                auto func = *reinterpret_cast<const config_section::delete_option_callback*>(pointer);
=======
                                                       config_section::read_callback *read_cb,
                                                       config_section::write_callback *write_cb,
                                                       config_section::write_default_callback *write_default_cb,
                                                       config_section::create_option_callback *create_cb,
                                                       config_section::delete_option_callback *delete_cb) {
        return globals::plugin->config_new_section(
            file, name, user_can_add_options, user_can_delete_options,
            read_cb ? static_cast<config_section::read_fn>([] (const void *pointer, void *, struct t_config_file *file,
                struct t_config_section *section, const char *key, const char *value) {
                auto& func = *reinterpret_cast<const config_section::read_callback*>(pointer);
                config_file file_(file);
                config_section section_(section);
                return func(file_, section_, key, value);
            }) : nullptr, read_cb, nullptr,
            write_cb ? static_cast<config_section::write_fn>([] (const void *pointer, void *, struct t_config_file *file, const char *name) {
                auto& func = *reinterpret_cast<const config_section::write_callback*>(pointer);
                config_file file_(file);
                return func(file_, name);
            }) : nullptr, write_cb, nullptr,
            write_default_cb ? static_cast<config_section::write_default_fn>([] (const void *pointer, void *, struct t_config_file *file, const char *name) {
                auto& func = *reinterpret_cast<const config_section::write_default_callback*>(pointer);
                config_file file_(file);
                return func(file_, name);
            }) : nullptr, write_default_cb, nullptr,
            create_cb ? static_cast<config_section::create_option_fn>([] (const void *pointer, void *, struct t_config_file *file,
                struct t_config_section *section, const char *key, const char *value) {
                auto& func = *reinterpret_cast<const config_section::create_option_callback*>(pointer);
                config_file file_(file);
                config_section section_(section);
                return func(file_, section_, key, value);
            }) : nullptr, create_cb, nullptr,
            delete_cb ? static_cast<config_section::delete_option_fn>([] (const void *pointer, void *, struct t_config_file *file,
                struct t_config_section *section, struct t_config_option *option) {
                auto& func = *reinterpret_cast<const config_section::delete_option_callback*>(pointer);
>>>>>>> Stashed changes
                config_file file_(file);
                config_section section_(section);
                config_option option_(option);
                return func(file_, section_, option_);
<<<<<<< Updated upstream
            }, &delete_cb, nullptr);
=======
            }) : nullptr, delete_cb, nullptr);
>>>>>>> Stashed changes
    }
    inline struct t_config_section *config_search_section(struct t_config_file *config_file,
                                                          const char *section_name) {
        return globals::plugin->config_search_section(config_file, section_name);
    }
    inline struct t_config_option *config_new_option(struct t_config_file *config_file,
                                                     struct t_config_section *section,
                                                     const char *name, const char *type,
                                                     const char *description,
                                                     const char *string_values,
                                                     int min, int max,
                                                     const char *default_value,
                                                     const char *value,
                                                     bool null_value_allowed,
<<<<<<< Updated upstream
                                                     config_option::check_callback& check_value_cb,
                                                     config_option::change_callback& change_cb,
                                                     config_option::delete_callback& delete_cb) {
=======
                                                     config_option::check_callback *check_value_cb,
                                                     config_option::change_callback *change_cb,
                                                     config_option::delete_callback *delete_cb) {
>>>>>>> Stashed changes
        return globals::plugin->config_new_option(
            config_file, section,
            name, type, description, string_values,
            min, max, default_value, value, null_value_allowed,
<<<<<<< Updated upstream
            [] (const void *pointer, void *, struct t_config_option *option, const char *value) {
                auto func = *reinterpret_cast<const config_option::check_callback*>(pointer);
                config_option option_(option);
                return static_cast<int>(func(option_, value));
            }, &check_value_cb, nullptr,
            [] (const void *pointer, void *, struct t_config_option *option) {
                auto func = *reinterpret_cast<const config_option::change_callback*>(pointer);
                config_option option_(option);
                return func(option_);
            }, &change_cb, nullptr,
            [] (const void *pointer, void *, struct t_config_option *option) {
                auto func = *reinterpret_cast<const config_option::delete_callback*>(pointer);
                config_option option_(option);
                return func(option_);
            }, &delete_cb, nullptr);
=======
            check_value_cb ? static_cast<config_option::check_fn>([] (const void *pointer, void *, struct t_config_option *option, const char *value) {
                auto& func = *reinterpret_cast<const config_option::check_callback*>(pointer);
                config_option option_(option);
                return static_cast<int>(func(option_, value));
            }) : nullptr, check_value_cb, nullptr,
            change_cb ? static_cast<config_option::change_fn>([] (const void *pointer, void *, struct t_config_option *option) {
                auto& func = *reinterpret_cast<const config_option::change_callback*>(pointer);
                config_option option_(option);
                return func(option_);
            }) : nullptr, change_cb, nullptr,
            delete_cb ? static_cast<config_option::delete_fn>([] (const void *pointer, void *, struct t_config_option *option) {
                auto& func = *reinterpret_cast<const config_option::delete_callback*>(pointer);
                config_option option_(option);
                return func(option_);
            }) : nullptr, delete_cb, nullptr);
>>>>>>> Stashed changes
    }
    inline struct t_config_option *config_search_option(struct t_config_file *config_file,
                                                        struct t_config_section *section,
                                                        const char *option_name) {
        return globals::plugin->config_search_option(config_file, section, option_name);
    }
    inline void config_search_section_option(struct t_config_file *config_file,
                                             struct t_config_section *section,
                                             const char *option_name,
                                             struct t_config_section **section_found,
                                             struct t_config_option **option_found) {
        return globals::plugin->config_search_section_option(config_file, section, option_name, section_found, option_found);
    }
    inline void config_search_with_string(const char *option_name,
                                          struct t_config_file **config_file,
                                          struct t_config_section **section,
                                          struct t_config_option **option,
                                          char **pos_option_name) {
        return globals::plugin->config_search_with_string(option_name, config_file, section, option, pos_option_name);
    }
    inline int config_string_to_boolean(const char *text) {
        return globals::plugin->config_string_to_boolean(text);
    }
    inline int config_option_reset(struct t_config_option *option,
                                   int run_callback) {
        return globals::plugin->config_option_reset(option, run_callback);
    }
    inline int config_option_set(struct t_config_option *option,
                                 const char *value, int run_callback) {
        return globals::plugin->config_option_set(option, value, run_callback);
    }
    inline int config_option_set_null(struct t_config_option *option,
                                      int run_callback) {
        return globals::plugin->config_option_set_null(option, run_callback);
    }
    inline int config_option_unset(struct t_config_option *option) {
        return globals::plugin->config_option_unset(option);
    }
    inline void config_option_rename(struct t_config_option *option,
                                     const char *new_name) {
        return globals::plugin->config_option_rename(option, new_name);
    }
    inline const char *config_option_get_string(struct t_config_option *option,
                                                const char *property) {
        return globals::plugin->config_option_get_string(option, property);
    }
    template<typename T>
    inline T *config_option_get_pointer(struct t_config_option *option,
                                           const char *property) {
        return static_cast<T>(
            globals::plugin->config_option_get_pointer(option, property));
    }
    inline int config_option_is_null(struct t_config_option *option) {
        return globals::plugin->config_option_is_null(option);
    }
    inline int config_option_default_is_null(struct t_config_option *option) {
        return globals::plugin->config_option_default_is_null(option);
    }
    inline int config_boolean(struct t_config_option *option) {
        return globals::plugin->config_boolean(option);
    }
    inline int config_boolean_default(struct t_config_option *option) {
        return globals::plugin->config_boolean_default(option);
    }
    inline int config_integer(struct t_config_option *option) {
        return globals::plugin->config_integer(option);
    }
    inline int config_integer_default(struct t_config_option *option) {
        return globals::plugin->config_integer_default(option);
    }
    inline const char *config_string(struct t_config_option *option) {
        return globals::plugin->config_string(option);
    }
    inline const char *config_string_default(struct t_config_option *option) {
        return globals::plugin->config_string_default(option);
    }
    inline const char *config_color(struct t_config_option *option) {
        return globals::plugin->config_color(option);
    }
    inline const char *config_color_default(struct t_config_option *option) {
        return globals::plugin->config_color_default(option);
    }
    inline int config_write_option(struct t_config_file *config_file,
                                   struct t_config_option *option) {
        return globals::plugin->config_write_option(config_file, option);
    }
    template<typename... Args>
    inline int config_write_line(struct t_config_file *config_file,
                                 const char *option_name,
                                 const char *value, Args... args) {
        return globals::plugin->config_write_line(config_file, option_name, value, args...);
    }
    inline int config_write(struct t_config_file *config_file) {
        return globals::plugin->config_write(config_file);
    }
    inline int config_read(struct t_config_file *config_file) {
        return globals::plugin->config_read(config_file);
    }
    inline int config_reload(struct t_config_file *config_file) {
        return globals::plugin->config_reload(config_file);
    }
    inline void config_option_free(struct t_config_option *option) {
        return globals::plugin->config_option_free(option);
    }
    inline void config_section_free_options(struct t_config_section *section) {
        return globals::plugin->config_section_free_options(section);
    }
    inline void config_section_free(struct t_config_section *section) {
        return globals::plugin->config_section_free(section);
    }
    inline void config_free(struct t_config_file *config_file) {
        return globals::plugin->config_free(config_file);
    }
    inline struct t_config_option *config_get(const char *option_name) {
        return globals::plugin->config_get(option_name);
    }
    inline const char *config_get_plugin(const char *option_name) {
        return globals::plugin->config_get_plugin(globals::plugin, option_name);
    }
    inline int config_is_set_plugin(const char *option_name) {
        return globals::plugin->config_is_set_plugin(globals::plugin, option_name);
    }
    inline int config_set_plugin(const char *option_name, const char *value) {
        return globals::plugin->config_set_plugin(globals::plugin, option_name, value);
    }
    inline void config_set_desc_plugin(const char *option_name,
                                       const char *description) {
        return globals::plugin->config_set_desc_plugin(globals::plugin, option_name, description);
    }
    inline int config_unset_plugin(const char *option_name) {
        return globals::plugin->config_unset_plugin(globals::plugin, option_name);
    }

    inline int key_bind(const char *context, struct t_hashtable *keys) {
        return globals::plugin->key_bind(context, keys);
    }
    inline int key_unbind(const char *context, const char *key) {
        return globals::plugin->key_unbind(context, key);
    }

    inline const char *prefix(const char *prefix) {
        return globals::plugin->prefix(prefix);
    }
    inline const char *color(const char *color_name) {
        return globals::plugin->color(color_name);
    }
    template<typename... Args>
    inline void printf(struct t_gui_buffer *buffer, const char *message, Args... args) {
        return globals::plugin->printf_date_tags(
            buffer, 0, nullptr, message, args...);
    }
    template<typename... Args>
    inline void printf_date_tags(struct t_gui_buffer *buffer, time_t date,
                                 const char *tags, const char *message, Args... args) {
        return globals::plugin->printf_date_tags(buffer, date, tags, message, args...);
    }
    template<typename... Args>
    inline void printf_y(struct t_gui_buffer *buffer, int y,
                         const char *message, Args... args) {
        return globals::plugin->printf_y(buffer, y, message, args...);
    }
    template<typename... Args>
    inline void log_printf(const char *message, Args... args) {
        return globals::plugin->log_printf(message, args...);
    }

    inline struct t_hook *hook_command(const char *command,
                                       const char *description,
                                       const char *args,
                                       const char *args_description,
                                       const char *completion,
                                       int (*callback)(const void *pointer,
                                                       void *data,
                                                       struct t_gui_buffer *buffer,
                                                       int argc, char **argv,
                                                       char **argv_eol),
                                       const void *callback_pointer,
                                       void *callback_data) {
        return globals::plugin->hook_command(globals::plugin, command, description, args, args_description, completion, callback, callback_pointer, callback_data);
    }
    inline struct t_hook *hook_command_run(const char *command,
                                           int (*callback)(const void *pointer,
                                                           void *data,
                                                           struct t_gui_buffer *buffer,
                                                           const char *command),
                                           const void *callback_pointer,
                                           void *callback_data) {
        return globals::plugin->hook_command_run(globals::plugin, command, callback, callback_pointer, callback_data);
    }
    inline struct t_hook *hook_timer(
        long interval,
        int align_second,
        int max_calls,
        hook::timer_callback *callback) {
        return globals::plugin->hook_timer(
            globals::plugin,
            interval, align_second, max_calls,
            callback ? static_cast<hook::timer_fn>([] (const void *pointer, void *, int remaining_calls) {
<<<<<<< Updated upstream
                auto func = *reinterpret_cast<const hook::timer_callback*>(pointer);
=======
                auto& func = *reinterpret_cast<const hook::timer_callback*>(pointer);
>>>>>>> Stashed changes
                return static_cast<int>(func(remaining_calls));
            }) : nullptr, callback, nullptr);
    }
    inline struct t_hook *hook_fd(int fd,
                                  int flag_read,
                                  int flag_write,
                                  int flag_exception,
                                  int (*callback)(const void *pointer,
                                                  void *data,
                                                  int fd),
                                  const void *callback_pointer,
                                  void *callback_data) {
        return globals::plugin->hook_fd(globals::plugin, fd, flag_read, flag_write, flag_exception, callback, callback_pointer, callback_data);
    }
    inline struct t_hook *hook_process(const char *command,
                                       int timeout,
                                       int (*callback)(const void *pointer,
                                                       void *data,
                                                       const char *command,
                                                       int return_code,
                                                       const char *out,
                                                       const char *err),
                                       const void *callback_pointer,
                                       void *callback_data) {
        return globals::plugin->hook_process(globals::plugin, command, timeout, callback, callback_pointer, callback_data);
    }
    inline struct t_hook *hook_process_hashtable(const char *command,
                                                 struct t_hashtable *options,
                                                 int timeout,
                                                 int (*callback)(const void *pointer,
                                                                 void *data,
                                                                 const char *command,
                                                                 int return_code,
                                                                 const char *out,
                                                                 const char *err),
                                                 const void *callback_pointer,
                                                 void *callback_data) {
        return globals::plugin->hook_process_hashtable(globals::plugin, command, options, timeout, callback, callback_pointer, callback_data);
    }
    inline struct t_hook *hook_connect(const char *proxy,
                                       const char *address,
                                       int port,
                                       int ipv6,
                                       int retry,
                                       void *gnutls_sess, void *gnutls_cb,
                                       int gnutls_dhkey_size,
                                       const char *gnutls_priorities,
                                       const char *local_hostname,
                                       int (*callback)(const void *pointer,
                                                       void *data,
                                                       int status,
                                                       int gnutls_rc,
                                                       int sock,
                                                       const char *error,
                                                       const char *ip_address),
                                       const void *callback_pointer,
                                       void *callback_data) {
        return globals::plugin->hook_connect(globals::plugin, proxy, address, port, ipv6, retry, gnutls_sess, gnutls_cb, gnutls_dhkey_size, gnutls_priorities, local_hostname, callback, callback_pointer, callback_data);
    }
    inline struct t_hook *hook_line(const char *buffer_type,
                                    const char *buffer_name,
                                    const char *tags,
                                    struct t_hashtable *(*callback)(const void *pointer,
                                                                    void *data,
                                                                    struct t_hashtable *line),
                                    const void *callback_pointer,
                                    void *callback_data) {
        return globals::plugin->hook_line(globals::plugin, buffer_type, buffer_name, tags, callback, callback_pointer, callback_data);
    }
    inline struct t_hook *hook_print(struct t_gui_buffer *buffer,
                                     const char *tags,
                                     const char *message,
                                     int strip_colors,
                                     int (*callback)(const void *pointer,
                                                     void *data,
                                                     struct t_gui_buffer *buffer,
                                                     time_t date,
                                                     int tags_count,
                                                     const char **tags,
                                                     int displayed,
                                                     int highlight,
                                                     const char *prefix,
                                                     const char *message),
                                     const void *callback_pointer,
                                     void *callback_data) {
        return globals::plugin->hook_print(globals::plugin, buffer, tags, message, strip_colors, callback, callback_pointer, callback_data);
    }
    inline struct t_hook *hook_signal(const char *signal,
                                      int (*callback)(const void *pointer,
                                                      void *data,
                                                      const char *signal,
                                                      const char *type_data,
                                                      void *signal_data),
                                      const void *callback_pointer = nullptr,
                                      void *callback_data = nullptr) {
        return globals::plugin->hook_signal(globals::plugin, signal, callback, callback_pointer, callback_data);
    }
    template<typename T>
    inline int hook_signal_send(const char *signal, const char *type_data,
                                T signal_data) {
        return globals::plugin->hook_signal_send(signal, type_data, signal_data);
    }
    inline struct t_hook *hook_hsignal(const char *signal,
                                       int (*callback)(const void *pointer,
                                                       void *data,
                                                       const char *signal,
                                                       struct t_hashtable *hashtable),
                                       const void *callback_pointer,
                                       void *callback_data) {
        return globals::plugin->hook_hsignal(globals::plugin, signal, callback, callback_pointer, callback_data);
    }
    inline int hook_hsignal_send(const char *signal,
                                 struct t_hashtable *hashtable) {
        return globals::plugin->hook_hsignal_send(signal, hashtable);
    }
    inline struct t_hook *hook_config(const char *option,
                                      int (*callback)(const void *pointer,
                                                      void *data,
                                                      const char *option,
                                                      const char *value),
                                      const void *callback_pointer,
                                      void *callback_data) {
        return globals::plugin->hook_config(globals::plugin, option, callback, callback_pointer, callback_data);
    }
    inline struct t_hook *hook_completion(const char *completion_item,
                                          const char *description,
                                          int (*callback)(const void *pointer,
                                                          void *data,
                                                          const char *completion_item,
                                                          struct t_gui_buffer *buffer,
                                                          struct t_gui_completion *completion),
                                          const void *callback_pointer,
                                          void *callback_data) {
        return globals::plugin->hook_completion(globals::plugin, completion_item, description, callback, callback_pointer, callback_data);
    }
    inline const char *hook_completion_get_string(struct t_gui_completion *completion,
                                                  const char *property) {
        return globals::plugin->hook_completion_get_string(completion, property);
    }
    inline void hook_completion_list_add(struct t_gui_completion *completion,
                                         const char *word,
                                         int nick_completion,
                                         const char *where) {
        return globals::plugin->hook_completion_list_add(completion, word, nick_completion, where);
    }
    inline struct t_hook *hook_modifier(const char *modifier,
                                        char *(*callback)(const void *pointer,
                                                          void *data,
                                                          const char *modifier,
                                                          const char *modifier_data,
                                                          const char *string),
                                        const void *callback_pointer,
                                        void *callback_data) {
        return globals::plugin->hook_modifier(globals::plugin, modifier, callback, callback_pointer, callback_data);
    }
    inline char *hook_modifier_exec(const char *modifier,
                                    const char *modifier_data,
                                    const char *string) {
        return globals::plugin->hook_modifier_exec(globals::plugin, modifier, modifier_data, string);
    }
    inline struct t_hook *hook_info(const char *info_name,
                                    const char *description,
                                    const char *args_description,
                                    char *(*callback)(const void *pointer,
                                                      void *data,
                                                      const char *info_name,
                                                      const char *arguments),
                                    const void *callback_pointer,
                                    void *callback_data) {
        return globals::plugin->hook_info(globals::plugin, info_name, description, args_description, callback, callback_pointer, callback_data);
    }
    inline struct t_hook *hook_info_hashtable(const char *info_name,
                                              const char *description,
                                              const char *args_description,
                                              const char *output_description,
                                              struct t_hashtable *(*callback)(const void *pointer,
                                                                              void *data,
                                                                              const char *info_name,
                                                                              struct t_hashtable *hashtable),
                                              const void *callback_pointer,
                                              void *callback_data) {
        return globals::plugin->hook_info_hashtable(globals::plugin, info_name, description, args_description, output_description, callback, callback_pointer, callback_data);
    }
    inline struct t_hook *hook_infolist(const char *infolist_name,
                                        const char *description,
                                        const char *pointer_description,
                                        const char *args_description,
                                        struct t_infolist *(*callback)(const void *cb_pointer,
                                                                       void *data,
                                                                       const char *infolist_name,
                                                                       void *obj_pointer,
                                                                       const char *arguments),
                                        const void *callback_pointer,
                                        void *callback_data) {
        return globals::plugin->hook_infolist(globals::plugin, infolist_name, description, pointer_description, args_description, callback, callback_pointer, callback_data);
    }
    inline struct t_hook *hook_hdata(const char *hdata_name,
                                     const char *description,
                                     struct t_hdata *(*callback)(const void *pointer,
                                                                 void *data,
                                                                 const char *hdata_name),
                                     const void *callback_pointer,
                                     void *callback_data) {
        return globals::plugin->hook_hdata(globals::plugin, hdata_name, description, callback, callback_pointer, callback_data);
    }
    inline struct t_hook *hook_focus(const char *area,
                                     struct t_hashtable *(*callback)(const void *pointer,
                                                                     void *data,
                                                                     struct t_hashtable *info),
                                     const void *callback_pointer,
                                     void *callback_data) {
        return globals::plugin->hook_focus(globals::plugin, area, callback, callback_pointer, callback_data);
    }
    inline void hook_set(struct t_hook *hook, const char *property,
                         const char *value) {
        return globals::plugin->hook_set(hook, property, value);
    }
    inline void unhook(hook& hook) {
        return globals::plugin->unhook(hook);
    }
    inline void unhook_all(const char *plugin) {
        return globals::plugin->unhook_all(globals::plugin, plugin);
    }

    inline struct t_gui_buffer *buffer_new(const char *name,
                                           gui_buffer::input_callback& input_cb,
                                           gui_buffer::close_callback& close_cb) {
        return globals::plugin->buffer_new(
            globals::plugin,
            name,
            [] (const void *pointer, void *,
                struct t_gui_buffer *buffer,
                const char *input_data) {
<<<<<<< Updated upstream
                auto func = *reinterpret_cast<const gui_buffer::input_callback*>(pointer);
=======
                auto& func = *reinterpret_cast<const gui_buffer::input_callback*>(pointer);
>>>>>>> Stashed changes
                gui_buffer buffer_(buffer);
                return static_cast<int>(func(buffer_, input_data));
            }, &input_cb, nullptr,
            [] (const void *pointer, void *,
                struct t_gui_buffer *buffer) {
<<<<<<< Updated upstream
                auto func = *reinterpret_cast<const gui_buffer::close_callback*>(pointer);
=======
                auto& func = *reinterpret_cast<const gui_buffer::close_callback*>(pointer);
>>>>>>> Stashed changes
                gui_buffer buffer_(buffer);
                return static_cast<int>(func(buffer_));
            }, &close_cb, nullptr);
    }
    inline struct t_gui_buffer *buffer_search(const char *plugin, const char *name) {
        return globals::plugin->buffer_search(plugin, name);
    }
    inline struct t_gui_buffer *buffer_search_main() {
        return globals::plugin->buffer_search_main();
    }
    inline void buffer_clear(struct t_gui_buffer *buffer) {
        return globals::plugin->buffer_clear(buffer);
    }
    inline void buffer_close(struct t_gui_buffer *buffer) {
        return globals::plugin->buffer_close(buffer);
    }
    inline void buffer_merge(struct t_gui_buffer *buffer,
                             struct t_gui_buffer *target_buffer) {
        return globals::plugin->buffer_merge(buffer, target_buffer);
    }
    inline void buffer_unmerge(struct t_gui_buffer *buffer, int number) {
        return globals::plugin->buffer_unmerge(buffer, number);
    }
    inline int buffer_get_integer(struct t_gui_buffer *buffer,
                                  const char *property) {
        return globals::plugin->buffer_get_integer(buffer, property);
    }
    inline const char *buffer_get_string(struct t_gui_buffer *buffer,
                                         const char *property) {
        return globals::plugin->buffer_get_string(buffer, property);
    }
    template<typename T>
    inline T *buffer_get_pointer(struct t_gui_buffer *buffer,
                                    const char *property) {
        return static_cast<T>(
            globals::plugin->buffer_get_pointer(buffer, property));
    }
    inline void buffer_set(struct t_gui_buffer *buffer, const char *property,
                           const char *value) {
        return globals::plugin->buffer_set(buffer, property, value);
    }
    inline void buffer_set_pointer(struct t_gui_buffer *buffer,
                                   const char *property, void *pointer) {
        return globals::plugin->buffer_set_pointer(buffer, property, pointer);
    }
    inline char *buffer_string_replace_local_var(struct t_gui_buffer *buffer,
                                                 const char *string) {
        return globals::plugin->buffer_string_replace_local_var(buffer, string);
    }
    inline int buffer_match_list(struct t_gui_buffer *buffer, const char *string) {
        return globals::plugin->buffer_match_list(buffer, string);
    }

    inline struct t_gui_window *window_search_with_buffer(struct t_gui_buffer *buffer) {
        return globals::plugin->window_search_with_buffer(buffer);
    }
    inline int window_get_integer(struct t_gui_window *window,
                                  const char *property) {
        return globals::plugin->window_get_integer(window, property);
    }
    inline const char *window_get_string(struct t_gui_window *window,
                                         const char *property) {
        return globals::plugin->window_get_string(window, property);
    }
    template<typename T>
    inline T *window_get_pointer(struct t_gui_window *window,
                                    const char *property) {
        return static_cast<T>(
            globals::plugin->window_get_pointer(window, property));
    }
    inline struct t_gui_window *current_window() {
        return static_cast<struct t_gui_window *>(
            globals::plugin->window_get_pointer(nullptr, "current"));
    }
    inline void window_set_title(const char *title) {
        return globals::plugin->window_set_title(title);
    }

    inline struct t_gui_nick_group *nicklist_add_group(struct t_gui_buffer *buffer,
                                                       struct t_gui_nick_group *parent_group,
                                                       const char *name,
                                                       const char *color,
                                                       int visible) {
        return globals::plugin->nicklist_add_group(buffer, parent_group, name, color, visible);
    }
    inline struct t_gui_nick_group *nicklist_search_group(struct t_gui_buffer *buffer,
                                                          struct t_gui_nick_group *from_group,
                                                          const char *name) {
        return globals::plugin->nicklist_search_group(buffer, from_group, name);
    }
    inline struct t_gui_nick *nicklist_add_nick(struct t_gui_buffer *buffer,
                                                struct t_gui_nick_group *group,
                                                const char *name,
                                                const char *color,
                                                const char *prefix,
                                                const char *prefix_color,
                                                int visible) {
        return globals::plugin->nicklist_add_nick(buffer, group, name, color, prefix, prefix_color, visible);
    }
    inline struct t_gui_nick *nicklist_search_nick(struct t_gui_buffer *buffer,
                                                   struct t_gui_nick_group *from_group,
                                                   const char *name) {
        return globals::plugin->nicklist_search_nick(buffer, from_group, name);
    }
    inline void nicklist_remove_group(struct t_gui_buffer *buffer,
                                      struct t_gui_nick_group *group) {
        return globals::plugin->nicklist_remove_group(buffer, group);
    }
    inline void nicklist_remove_nick(struct t_gui_buffer *buffer,
                                     struct t_gui_nick *nick) {
        return globals::plugin->nicklist_remove_nick(buffer, nick);
    }
    inline void nicklist_remove_all(struct t_gui_buffer *buffer) {
        return globals::plugin->nicklist_remove_all(buffer);
    }
    inline void nicklist_get_next_item(struct t_gui_buffer *buffer,
                                       struct t_gui_nick_group **group,
                                       struct t_gui_nick **nick) {
        return globals::plugin->nicklist_get_next_item(buffer, group, nick);
    }
    inline int nicklist_group_get_integer(struct t_gui_buffer *buffer,
                                          struct t_gui_nick_group *group,
                                          const char *property) {
        return globals::plugin->nicklist_group_get_integer(buffer, group, property);
    }
    inline const char *nicklist_group_get_string(struct t_gui_buffer *buffer,
                                                 struct t_gui_nick_group *group,
                                                 const char *property) {
        return globals::plugin->nicklist_group_get_string(buffer, group, property);
    }
    template<typename T>
    inline T *nicklist_group_get_pointer(struct t_gui_buffer *buffer,
                                            struct t_gui_nick_group *group,
                                            const char *property) {
        return static_cast<T>(
            globals::plugin->nicklist_group_get_pointer(buffer, group, property));
    }
    inline void nicklist_group_set(struct t_gui_buffer *buffer,
                                   struct t_gui_nick_group *group,
                                   const char *property, const char *value) {
        return globals::plugin->nicklist_group_set(buffer, group, property, value);
    }
    inline int nicklist_nick_get_integer(struct t_gui_buffer *buffer,
                                         struct t_gui_nick *nick,
                                         const char *property) {
        return globals::plugin->nicklist_nick_get_integer(buffer, nick, property);
    }
    inline const char *nicklist_nick_get_string(struct t_gui_buffer *buffer,
                                                struct t_gui_nick *nick,
                                                const char *property) {
        return globals::plugin->nicklist_nick_get_string(buffer, nick, property);
    }
    template<typename T>
    inline T *nicklist_nick_get_pointer(struct t_gui_buffer *buffer,
                                           struct t_gui_nick *nick,
                                           const char *property) {
        return static_cast<T>(
            globals::plugin->nicklist_nick_get_pointer(buffer, nick, property));
    }
    inline void nicklist_nick_set(struct t_gui_buffer *buffer,
                                  struct t_gui_nick *nick,
                                  const char *property, const char *value) {
        return globals::plugin->nicklist_nick_set(buffer, nick, property, value);
    }

    inline struct t_gui_bar_item *bar_item_search(const char *name) {
        return globals::plugin->bar_item_search(name);
    }
    inline struct t_gui_bar_item *bar_item_new(
        const char *name,
        gui_bar_item::build_callback& build_callback) {
        return globals::plugin->bar_item_new(
            globals::plugin,
            name, [] (const void *pointer, void *,
                      struct t_gui_bar_item *item,
                      struct t_gui_window *window,
                      struct t_gui_buffer *buffer,
                      struct t_hashtable *extra_args) {
<<<<<<< Updated upstream
                auto func = *reinterpret_cast<const gui_bar_item::build_callback*>(pointer);
=======
                auto& func = *reinterpret_cast<const gui_bar_item::build_callback*>(pointer);
>>>>>>> Stashed changes
                gui_bar_item item_(item);
                gui_buffer buffer_(buffer);
                auto res = func(item_, window, buffer_, extra_args);
                char *str = reinterpret_cast<char*>(
                    std::calloc(res.size() + 1, sizeof(char)));
                std::copy(res.begin(), res.end(), str);
                str[res.size()] = '\0';
                return str;
            }, &build_callback, nullptr);
    }
    inline void bar_item_update(const char *name) {
        return globals::plugin->bar_item_update(name);
    }
    inline void bar_item_remove(gui_bar_item& item) {
        return globals::plugin->bar_item_remove(item);
    }
    inline struct t_gui_bar *bar_search(const char *name) {
        return globals::plugin->bar_search(name);
    }
    inline struct t_gui_bar *bar_new(const char *name,
                                     const char *hidden,
                                     const char *priority,
                                     const char *type,
                                     const char *condition,
                                     const char *position,
                                     const char *filling_top_bottom,
                                     const char *filling_left_right,
                                     const char *size,
                                     const char *size_max,
                                     const char *color_fg,
                                     const char *color_delim,
                                     const char *color_bg,
                                     const char *color_bg_inactive,
                                     const char *separator,
                                     const char *items) {
        return globals::plugin->bar_new(name, hidden, priority, type, condition, position, filling_top_bottom, filling_left_right, size, size_max, color_fg, color_delim, color_bg, color_bg_inactive, separator, items);
    }
    inline int bar_set(struct t_gui_bar *bar, const char *property,
                       const char *value) {
        return globals::plugin->bar_set(bar, property, value);
    }
    inline void bar_update(const char *name) {
        return globals::plugin->bar_update(name);
    }
    inline void bar_remove(struct t_gui_bar *bar) {
        return globals::plugin->bar_remove(bar);
    }

    inline int command(struct t_gui_buffer *buffer, const char *command) {
        return globals::plugin->command(globals::plugin, buffer, command);
    }
    inline int command_options(struct t_gui_buffer *buffer, const char *command,
                               struct t_hashtable *options) {
        return globals::plugin->command_options(globals::plugin, buffer, command, options);
    }

    inline struct t_gui_completion *completion_new(struct t_gui_buffer *buffer) {
        return globals::plugin->completion_new(globals::plugin, buffer);
    }
    inline int completion_search(struct t_gui_completion *completion,
                                 const char *data, int position, int direction) {
        return globals::plugin->completion_search(completion, data, position, direction);
    }
    inline const char *completion_get_string(struct t_gui_completion *completion,
                                             const char *property) {
        return globals::plugin->completion_get_string(completion, property);
    }
    inline void completion_list_add(struct t_gui_completion *completion,
                                    const char *word,
                                    int nick_completion,
                                    const char *where) {
        return globals::plugin->completion_list_add(completion, word, nick_completion, where);
    }
    inline void completion_free(struct t_gui_completion *completion) {
        return globals::plugin->completion_free(completion);
    }

    inline int network_pass_proxy(const char *proxy, int sock,
                                  const char *address, int port) {
        return globals::plugin->network_pass_proxy(proxy, sock, address, port);
    }
    inline int network_connect_to(const char *proxy,
                                  struct sockaddr *address,
                                  socklen_t address_length) {
        return globals::plugin->network_connect_to(proxy, address, address_length);
    }

    inline char *info_get(const char *info_name, const char *arguments) {
        return globals::plugin->info_get(globals::plugin, info_name, arguments);
    }
    inline struct t_hashtable *info_get_hashtable(const char *info_name,
                                                  struct t_hashtable *hashtable) {
        return globals::plugin->info_get_hashtable(globals::plugin, info_name, hashtable);
    }

    inline struct t_infolist *infolist_new() {
        return globals::plugin->infolist_new(globals::plugin);
    }
    inline struct t_infolist_item *infolist_new_item(struct t_infolist *infolist) {
        return globals::plugin->infolist_new_item(infolist);
    }
    inline struct t_infolist_var *infolist_new_var_integer(struct t_infolist_item *item,
                                                           const char *name,
                                                           int value) {
        return globals::plugin->infolist_new_var_integer(item, name, value);
    }
    inline struct t_infolist_var *infolist_new_var_string(struct t_infolist_item *item,
                                                          const char *name,
                                                          const char *value) {
        return globals::plugin->infolist_new_var_string(item, name, value);
    }
    inline struct t_infolist_var *infolist_new_var_pointer(struct t_infolist_item *item,
                                                           const char *name,
                                                           void *pointer) {
        return globals::plugin->infolist_new_var_pointer(item, name, pointer);
    }
    inline struct t_infolist_var *infolist_new_var_buffer(struct t_infolist_item *item,
                                                          const char *name,
                                                          void *pointer,
                                                          int size) {
        return globals::plugin->infolist_new_var_buffer(item, name, pointer, size);
    }
    inline struct t_infolist_var *infolist_new_var_time(struct t_infolist_item *item,
                                                        const char *name,
                                                        time_t time) {
        return globals::plugin->infolist_new_var_time(item, name, time);
    }
    inline struct t_infolist_var *infolist_search_var(struct t_infolist *infolist,
                                                      const char *name) {
        return globals::plugin->infolist_search_var(infolist, name);
    }
    inline struct t_infolist *infolist_get(const char *infolist_name,
                                           void *pointer,
                                           const char *arguments) {
        return globals::plugin->infolist_get(globals::plugin, infolist_name, pointer, arguments);
    }
    inline int infolist_next(struct t_infolist *infolist) {
        return globals::plugin->infolist_next(infolist);
    }
    inline int infolist_prev(struct t_infolist *infolist) {
        return globals::plugin->infolist_prev(infolist);
    }
    inline void infolist_reset_item_cursor(struct t_infolist *infolist) {
        return globals::plugin->infolist_reset_item_cursor(infolist);
    }
    inline const char *infolist_fields(struct t_infolist *infolist) {
        return globals::plugin->infolist_fields(infolist);
    }
    inline int infolist_integer(struct t_infolist *infolist, const char *var) {
        return globals::plugin->infolist_integer(infolist, var);
    }
    inline const char *infolist_string(struct t_infolist *infolist, const char *var) {
        return globals::plugin->infolist_string(infolist, var);
    }
    template<typename T>
    inline T *infolist_pointer(struct t_infolist *infolist, const char *var) {
        return static_cast<T>(
            globals::plugin->infolist_pointer(infolist, var));
    }
    template<typename T>
    inline T *infolist_buffer(struct t_infolist *infolist, const char *var,
                                 int *size) {
        return static_cast<T>(
            globals::plugin->infolist_buffer(infolist, var, size));
    }
    inline time_t infolist_time(struct t_infolist *infolist, const char *var) {
        return globals::plugin->infolist_time(infolist, var);
    }
    inline void infolist_free(struct t_infolist *infolist) {
        return globals::plugin->infolist_free(infolist);
    }

    inline struct t_hdata *hdata_new(const char *hdata_name, const char *var_prev,
                                     const char *var_next,
                                     int create_allowed, int delete_allowed,
                                     int (*callback_update)(void *data,
                                                            struct t_hdata *hdata,
                                                            void *pointer,
                                                            struct t_hashtable *hashtable),
                                     void *callback_update_data) {
        return globals::plugin->hdata_new(globals::plugin, hdata_name, var_prev, var_next, create_allowed, delete_allowed, callback_update, callback_update_data);
    }
    inline void hdata_new_var(struct t_hdata *hdata, const char *name, int offset,
                              int type, int update_allowed, const char *array_size,
                              const char *hdata_name) {
        return globals::plugin->hdata_new_var(hdata, name, offset, type, update_allowed, array_size, hdata_name);
    }
    inline void hdata_new_list(struct t_hdata *hdata, const char *name,
                               void *pointer, int flags) {
        return globals::plugin->hdata_new_list(hdata, name, pointer, flags);
    }
    inline struct t_hdata *hdata_get(const char *hdata_name) {
        return globals::plugin->hdata_get(globals::plugin, hdata_name);
    }
    inline int hdata_get_var_offset(struct t_hdata *hdata, const char *name) {
        return globals::plugin->hdata_get_var_offset(hdata, name);
    }
    inline int hdata_get_var_type(struct t_hdata *hdata, const char *name) {
        return globals::plugin->hdata_get_var_type(hdata, name);
    }
    inline const char *hdata_get_var_type_string(struct t_hdata *hdata,
                                                 const char *name) {
        return globals::plugin->hdata_get_var_type_string(hdata, name);
    }
    inline int hdata_get_var_array_size(struct t_hdata *hdata, void *pointer,
                                        const char *name) {
        return globals::plugin->hdata_get_var_array_size(hdata, pointer, name);
    }
    inline const char *hdata_get_var_array_size_string(struct t_hdata *hdata,
                                                       void *pointer,
                                                       const char *name) {
        return globals::plugin->hdata_get_var_array_size_string(hdata, pointer, name);
    }
    inline const char *hdata_get_var_hdata(struct t_hdata *hdata,
                                           const char *name) {
        return globals::plugin->hdata_get_var_hdata(hdata, name);
    }
    template<typename T>
    inline T *hdata_get_var(struct t_hdata *hdata, void *pointer,
                               const char *name) {
        return static_cast<T>(
            globals::plugin->hdata_get_var(hdata, pointer, name));
    }
    template<typename T>
    inline T *hdata_get_var_at_offset(struct t_hdata *hdata, void *pointer,
                                         int offset) {
        return static_cast<T>(
            globals::plugin->hdata_get_var_at_offset(hdata, pointer, offset));
    }
    template<typename T>
    inline T *hdata_get_list(struct t_hdata *hdata, const char *name) {
        return static_cast<T>(
            globals::plugin->hdata_get_list(hdata, name));
    }
    inline int hdata_check_pointer(struct t_hdata *hdata, void *list,
                                   void *pointer) {
        return globals::plugin->hdata_check_pointer(hdata, list, pointer);
    }
    template<typename T>
    inline T *hdata_move(struct t_hdata *hdata, void *pointer, int count) {
        return static_cast<T>(
            globals::plugin->hdata_move(hdata, pointer, count));
    }
    template<typename T>
    inline T *hdata_search(struct t_hdata *hdata, void *pointer,
                              const char *search, int move) {
        return static_cast<T>(
            globals::plugin->hdata_search(hdata, pointer, search, move));
    }
    inline char hdata_char(struct t_hdata *hdata, void *pointer,
                           const char *name) {
        return globals::plugin->hdata_char(hdata, pointer, name);
    }
    inline int hdata_integer(struct t_hdata *hdata, void *pointer,
                             const char *name) {
        return globals::plugin->hdata_integer(hdata, pointer, name);
    }
    inline long hdata_long(struct t_hdata *hdata, void *pointer,
                           const char *name) {
        return globals::plugin->hdata_long(hdata, pointer, name);
    }
    inline const char *hdata_string(struct t_hdata *hdata, void *pointer,
                                    const char *name) {
        return globals::plugin->hdata_string(hdata, pointer, name);
    }
    template<typename T>
    inline T *hdata_pointer(struct t_hdata *hdata, void *pointer,
                               const char *name) {
        return static_cast<T>(
            globals::plugin->hdata_pointer(hdata, pointer, name));
    }
    inline time_t hdata_time(struct t_hdata *hdata, void *pointer,
                             const char *name) {
        return globals::plugin->hdata_time(hdata, pointer, name);
    }
    inline struct t_hashtable *hdata_hashtable(struct t_hdata *hdata,
                                               void *pointer, const char *name) {
        return globals::plugin->hdata_hashtable(hdata, pointer, name);
    }
    inline int hdata_compare(struct t_hdata *hdata,
                             void *pointer1, void *pointer2, const char *name,
                             int case_sensitive) {
        return globals::plugin->hdata_compare(hdata, pointer1, pointer2, name, case_sensitive);
    }
    inline int hdata_set(struct t_hdata *hdata, void *pointer, const char *name,
                         const char *value) {
        return globals::plugin->hdata_set(hdata, pointer, name, value);
    }
    inline int hdata_update(struct t_hdata *hdata, void *pointer,
                            struct t_hashtable *hashtable) {
        return globals::plugin->hdata_update(hdata, pointer, hashtable);
    }
    inline const char *hdata_get_string(struct t_hdata *hdata,
                                        const char *property) {
        return globals::plugin->hdata_get_string(hdata, property);
    }

    inline struct t_upgrade_file *upgrade_new(const char *filename,
                                              int (*callback_read)(const void *pointer,
                                                                   void *data,
                                                                   struct t_upgrade_file *upgrade_file,
                                                                   int object_id,
                                                                   struct t_infolist *infolist),
                                              const void *callback_read_pointer,
                                              void *callback_read_data) {
        return globals::plugin->upgrade_new(filename, callback_read, callback_read_pointer, callback_read_data);
    }
    inline int upgrade_write_object(struct t_upgrade_file *upgrade_file,
                                    int object_id,
                                    struct t_infolist *infolist) {
        return globals::plugin->upgrade_write_object(upgrade_file, object_id, infolist);
    }
    inline int upgrade_read(struct t_upgrade_file *upgrade_file) {
        return globals::plugin->upgrade_read(upgrade_file);
    }
    inline void upgrade_close(struct t_upgrade_file *upgrade_file) {
        return globals::plugin->upgrade_close(upgrade_file);
    }
}
