// Called when events happen: button clicked, entry needs editing
// src/ui/signals.c
#include <gtk/gtk.h>
#include "main_window.h"

void on_button_clicked(GtkButton *button, gpointer user_data) {
    set_text_view("Button Clicked!\n");
}
