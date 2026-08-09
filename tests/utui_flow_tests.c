#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

/*
 * Include the implementation so this regression test can exercise the real
 * event loop and its private Windows input queue without exposing test APIs.
 */
#include "../third_party/universal-tui/utui.c"

static int test_failures;

#define CHECK(expression)                                                     \
    do {                                                                      \
        if (!(expression)) {                                                  \
            fprintf(stderr,                                                   \
                    "FAIL %s:%d: %s\n",                                     \
                    __FILE__,                                                 \
                    __LINE__,                                                 \
                    #expression);                                             \
            ++test_failures;                                                  \
        }                                                                     \
    } while (0)

static UtItem flow_items[] = {
    UT_BOOL(2, "Enabled", "ENABLED", NULL),
};

static UtItem flow_root = UT_ROOT("Flow test", flow_items);

static HANDLE saved_stdout_handle;
static HANDLE null_output_handle = INVALID_HANDLE_VALUE;

static void silence_renderer(void)
{
    saved_stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    null_output_handle = CreateFileA(
        "NUL",
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (null_output_handle != INVALID_HANDLE_VALUE) {
        (void)SetStdHandle(STD_OUTPUT_HANDLE, null_output_handle);
    }
}

static void restore_renderer(void)
{
    if (null_output_handle != INVALID_HANDLE_VALUE) {
        (void)SetStdHandle(STD_OUTPUT_HANDLE, saved_stdout_handle);
        (void)CloseHandle(null_output_handle);
        null_output_handle = INVALID_HANDLE_VALUE;
    }
}

static void reset_runtime(UtApp *app)
{
    flow_items[0].value = 2;
    g_app = app;
    g_root_ptr = &flow_root;
    g_ascii = 1;
    g_rows = 24;
    g_cols = 80;
    g_cursx = -1;
    g_cursy = -1;
    g_quit = 0;
    g_resized = 0;
    g_saved_on_exit = 0;
    g_inq_h = 0;
    g_inq_t = 0;
    g_prevbtn = 0;
    g_depth = 0;
    init_tree(&flow_root);
    g_stack[0].menu = &flow_root;
    g_stack[0].sel = first_sel(&flow_root);
    g_stack[0].top = 0;
    g_stack[0].btn = 0;
    buf_resize();
}

static int file_contains(const char *path, const char *needle)
{
    char contents[1024];
    FILE *file = fopen(path, "rb");
    size_t length;

    if (file == NULL) {
        return 0;
    }
    length = fread(contents, 1u, sizeof(contents) - 1u, file);
    contents[length] = '\0';
    if (fclose(file) != 0) {
        return 0;
    }
    return strstr(contents, needle) != NULL;
}

static void test_save_success_exits(UtApp *app)
{
    int sentinel;

    reset_runtime(app);
    q_push('\t');
    q_push('\t');
    q_push('\t');
    q_push('\r');
    q_push('\r');
    q_push('\r');
    q_push(3);

    main_loop();

    sentinel = q_pop();
    CHECK(g_saved_on_exit == 1);
    CHECK(sentinel == 3);
    CHECK(file_contains(app->config_file, "CONFIG_FLOW_ENABLED=y"));
}

static void test_mouse_exit_propagates(UtApp *app)
{
    char mouse_sequence[48];
    int sequence_length;
    int sentinel;

    reset_runtime(app);
    draw_menu();
    CHECK(g_btn_n == 5);
    sequence_length = snprintf(
        mouse_sequence,
        sizeof(mouse_sequence),
        "\x1b[<0;%d;%dM",
        g_btn_x[1] + 1,
        g_btn_y + 1);
    CHECK(sequence_length > 0);
    CHECK((size_t)sequence_length < sizeof(mouse_sequence));
    if (sequence_length <= 0 ||
        (size_t)sequence_length >= sizeof(mouse_sequence)) {
        return;
    }

    q_pushs(mouse_sequence);
    q_push('n');
    q_push(3);

    main_loop();

    sentinel = q_pop();
    CHECK(g_saved_on_exit == 0);
    CHECK(sentinel == 3);
}

int main(void)
{
    char config_path[MAX_PATH];
    UtApp app;
    int path_length;

    path_length = snprintf(
        config_path,
        sizeof(config_path),
        "utui-flow-%lu.config",
        (unsigned long)GetCurrentProcessId());
    if (path_length <= 0 || (size_t)path_length >= sizeof(config_path)) {
        fputs("FAIL: could not create the temporary configuration path\n", stderr);
        return 1;
    }
    (void)remove(config_path);

    memset(&app, 0, sizeof(app));
    app.backtitle = "Universal-TUI flow regression test";
    app.title = "Universal-TUI flow regression test";
    app.config_file = config_path;
    app.sym_prefix = "FLOW";
    app.instructions = "Regression test";
    app.app_name = "utui-flow-tests";
    app.ascii = 1;
    app.exit_after_save = 1;

    silence_renderer();
    test_save_success_exits(&app);
    (void)remove(config_path);
    test_mouse_exit_propagates(&app);
    restore_renderer();

    (void)remove(config_path);
    free(g_buf);
    g_buf = NULL;
    g_bw = 0;
    g_bh = 0;

    if (test_failures != 0) {
        fprintf(stderr, "%d Universal-TUI flow test(s) failed\n", test_failures);
        return 1;
    }
    puts("Universal-TUI flow tests passed");
    return 0;
}
