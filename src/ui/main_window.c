// src/ui/main_window.c
#include "main_window.h"
#include "glibconfig.h"
#include "gtk/gtk.h"
#include "signals.h" // if you're separating signal handlers

GtkWidget *text_view;

GtkWidget* main_window_create(void) 
{
    // Create main window
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Hacking Tool");
    gtk_window_set_default_size(GTK_WINDOW(window), 1000, 700);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    // Create a button
    GtkWidget *button = gtk_button_new_with_label("Click Me");
    g_signal_connect(button, "clicked", G_CALLBACK(on_button_clicked), NULL);

    // Create scrollable TextView to show output
    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

    text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(text_view), FALSE);

    gtk_container_add(GTK_CONTAINER(scrolled_window), text_view);

    // Add widgets to layout
    gtk_box_pack_start(GTK_BOX(vbox), button, FALSE, FALSE, 10);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled_window, TRUE, TRUE, 0);

    gtk_container_add(GTK_CONTAINER(window), vbox);

    // Connect window close signal
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    return window;
}

// Set the text of any text view
void set_text_view(const char *text)
{
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));

    // Get iterator at the end of the buffer
    GtkTextIter end_iter;
    gtk_text_buffer_get_end_iter(buffer, &end_iter);

    // Append text
    gtk_text_buffer_insert(buffer, &end_iter, text, -1);
}
