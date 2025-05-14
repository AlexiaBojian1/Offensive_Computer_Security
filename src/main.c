#include "ui/main_window.h"

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    GtkWidget *window = main_window_create();
    gtk_widget_show_all(window);

    gtk_main();
    return 0;
}
