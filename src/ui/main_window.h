// src/ui/main_window.h
#ifndef MAIN_WINDOW_H
#define MAIN_WINDOW_H

#include <gtk/gtk.h>

// Main window creation
GtkWidget* main_window_create(void);
void set_text_view(const char*);

#endif // MAIN_WINDOW_H