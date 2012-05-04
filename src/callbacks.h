#include <gnome.h>

void
before_quit                      (GtkWidget       *widget,
                                        gpointer         user_data);
void
on_window1_show                        (GtkWidget       *widget,
                                        gpointer         user_data);
void
on_window2_show                        (GtkWidget       *widget,
                                        gpointer         user_data);

void
on_button3_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
on_button1_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
on_button4_clicked                     (GtkButton       *button,
                                        gpointer         user_data);

void
delete_event                     (GtkButton       *button,
                                        gpointer         user_data);

void delete_getAtrBox();
