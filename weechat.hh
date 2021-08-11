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

namespace weechat {
    extern "C" {
#include <weechat/weechat-plugin.h>

        class config_option; //typedef struct t_config_option config_option;
        class config_section; //typedef struct t_config_section config_section;
        class config_file; //typedef struct t_config_file config_file;
        typedef struct t_gui_window gui_window;
        class gui_buffer; //typedef struct t_gui_buffer gui_buffer;
        typedef struct t_gui_bar gui_bar;
        class gui_bar_item; //typedef struct t_gui_bar_item gui_bar_item;
        typedef struct t_gui_bar_window gui_bar_window;
        typedef struct t_gui_completion gui_completion;
        typedef struct t_gui_nick gui_nick;
        typedef struct t_gui_nick_group gui_nick_group;
        typedef struct t_infolist infolist;
        typedef struct t_infolist_item infolist_item;
        typedef struct t_upgrade_file upgrade_file;
        typedef struct t_weelist weelist;
        typedef struct t_weelist_item weelist_item;
        typedef struct t_arraylist arraylist;
        typedef struct t_hashtable hashtable;
        typedef struct t_hdata hdata;
        class hook; //typedef struct t_hook hook;
        class plugin; //typedef struct t_weechat_plugin weechat_plugin;
    }

    enum errc : int {
        ok = WEECHAT_RC_OK,
        eat = WEECHAT_RC_OK_EAT,
        err = WEECHAT_RC_ERROR,
    };

    class error : virtual public std::runtime_error {
    public:
        explicit inline error(const std::string_view subject)
            : std::runtime_error(std::string(subject)) {
        }
        virtual ~error() throw () {}
    };

    class config_option : public std::reference_wrapper<struct t_config_option> {
    public:
        typedef int (*check_fn)(const void *, void *, struct t_config_option *, const char *);
        typedef std::function<bool(config_option& option, std::string value)> check_callback;
        typedef void (*change_fn)(const void *, void *, struct t_config_option *);
        typedef std::function<void(config_option& option)> change_callback;
        typedef void (*delete_fn)(const void *, void *, struct t_config_option *);
        typedef std::function<void(config_option& option)> delete_callback;

        config_option(
            config_file& config_file, config_section& section, std::string name,
            std::string type, std::string description, std::string string_values,
            int min, int max, std::string default_value, std::string value, bool null_value_allowed,
            check_callback check_value_cb, change_callback change_cb, delete_callback delete_cb);
        explicit config_option(struct t_config_option* config_option);
        inline ~config_option() {}

        inline operator struct t_config_option* () const { return &this->get(); }
        operator int () const;
        operator bool () const;
        operator std::string () const;
        std::string string(std::string property) const;
        template<typename T> T *pointer(std::string property) const;
        config_option& operator= (std::string_view value);
        inline config_option& operator= (struct t_config_option* config_option_ptr) {
            *this = config_option_ptr;
            return *this;
        }

        inline std::string name() const { return this->m_name; }

    private:
        check_callback m_check_cb;
        change_callback m_change_cb;
        delete_callback m_delete_cb;
        std::string m_name;
    };

    class config_section : public std::reference_wrapper<struct t_config_section> {
    public:
        typedef int (*read_fn)(const void *, void *, struct t_config_file *, struct t_config_section *,
                               const char *, const char *);
        typedef std::function<int(config_file& config_file, config_section& section,
                                  std::string option_name, std::string value)> read_callback;
        typedef int (*write_fn)(const void *, void *, struct t_config_file *, const char *);
        typedef std::function<int(config_file& config_file,
                                  std::string section_name)> write_callback;
        typedef int (*write_default_fn)(const void *, void *, struct t_config_file *, const char *);
        typedef std::function<int(config_file& config_file,
                                  std::string section_name)> write_default_callback;
        typedef int (*create_option_fn)(const void *, void *, struct t_config_file *, struct t_config_section *,
                                        const char *, const char *);
        typedef std::function<int(config_file& config_file, config_section& section,
                                  std::string option_name, std::string value)> create_option_callback;
        typedef int (*delete_option_fn)(const void *, void *, struct t_config_file *, struct t_config_section *,
                                        struct t_config_option *);
        typedef std::function<int(config_file& config_file, config_section& section,
                                  config_option& option)> delete_option_callback;

        config_section(
            config_file& config_file, std::string name,
            bool user_can_add_options, bool user_can_delete_options,
            read_callback read_cb, write_callback write_cb,
            write_default_callback write_default_cb,
            create_option_callback create_option_cb,
            delete_option_callback delete_option_cb);
        explicit config_section(struct t_config_section* config_section);
        inline ~config_section() {}

        inline operator struct t_config_section* () const { return &this->get(); }
        inline config_section& operator= (struct t_config_section* config_section_ptr) {
            *this = config_section_ptr;
            return *this;
        }

        inline std::string name() const { return this->m_name; }

    private:
        std::string m_name;

        read_callback m_read_cb;
        write_callback m_write_cb;
        write_default_callback m_write_default_cb;
        create_option_callback m_create_option_cb;
        delete_option_callback m_delete_option_cb;
    };

    class config_file : public std::reference_wrapper<struct t_config_file> {
    public:
        typedef int (*reload_fn)(const void *, void *, struct t_config_file *);
        typedef std::function<int(config_file& config_file)> reload_callback;

        config_file(std::string name, reload_callback reload_cb);
        explicit config_file(struct t_config_file* config_file);
        inline ~config_file() {}

        inline operator struct t_config_file* () const { return &this->get(); }
        inline config_file& operator= (struct t_config_file* config_file_ptr) {
            *this = config_file_ptr;
            return *this;
        }

        inline std::string name() const { return this->m_name; }

    private:
        std::string m_name;

        reload_callback m_reload_cb;
    };

    class gui_buffer : std::reference_wrapper<struct t_gui_buffer> {
    public:
        typedef int (*input_fn)(const void *, void *, struct t_gui_buffer *, const char *);
        typedef std::function<errc(gui_buffer& buffer,
                                   std::string input_data)> input_callback;
        typedef int (*close_fn)(const void *, void *, struct t_gui_buffer *);
        typedef std::function<errc(gui_buffer& buffer)> close_callback;

        gui_buffer(std::string name, input_callback input_cb, close_callback close_cb);
        explicit gui_buffer(struct t_gui_buffer* gui_buffer);
        ~gui_buffer();

        inline operator struct t_gui_buffer* () const { return &this->get(); }
        inline gui_buffer& operator= (struct t_gui_buffer* gui_buffer_ptr) {
            *this = gui_buffer_ptr;
            return *this;
        }

        std::string name;

    private:
        input_callback m_input_cb;
        close_callback m_close_cb;
    };

    class gui_bar_item : public std::reference_wrapper<struct t_gui_bar_item> {
    public:
        typedef char* (*build_fn)(const void *, void *, struct t_gui_bar_item *, struct t_gui_window *,
                                  struct t_gui_buffer *, struct t_hashtable *);
        typedef std::function<std::string(gui_bar_item&, gui_window*,
                                          gui_buffer&, hashtable*)> build_callback;

        gui_bar_item(std::string_view name, build_callback callback);
        explicit gui_bar_item(struct t_gui_bar_item* item);
        ~gui_bar_item();

        void update(std::string_view name);

        inline operator struct t_gui_bar_item* () const { return &this->get(); }
        inline gui_bar_item& operator= (struct t_gui_bar_item* item_ptr) {
            *this = item_ptr;
            return *this;
        }

        static gui_bar_item search(std::string_view name);

    private:
        build_callback m_cb;
    };

    class hook : public std::reference_wrapper<struct t_hook> {
    public:
        typedef int (*timer_fn)(const void *, void *, int remaining_calls);
        typedef std::function<errc(int remaining_calls)> timer_callback;

        hook(long interval, int align_second, int max_calls, timer_callback callback);
        explicit hook(struct t_hook* hook);
        ~hook();

        inline operator struct t_hook* () const { return &this->get(); }
        inline hook& operator= (struct t_hook* hook_ptr) {
            *this = hook_ptr;
            return *this;
        }

    private:
        union {
            timer_callback m_timer_cb;
        };
    };
}
