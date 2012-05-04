#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gtk/gtk.h>
#include <glib/gi18n-lib.h>
#include "eggtrayicon.h"
#include "tray.h"
#include "../pixmaps/connecting.xpm"
#include "../pixmaps/connecting1.xpm"
#include "../pixmaps/connecting2.xpm"

int j=0;
	EggTrayIcon *tray_icon;
	GtkWidget *event_box;
	int pix;
	GtkWidget *image;
	GtkTooltips *tooltips;
gboolean
tray_button_press_event_cb (GtkWidget * button, GdkEventButton * event,
			    tray_demo * tray)
{
	g_return_val_if_fail (tray, FALSE);
	g_return_val_if_fail ((event->type == GDK_BUTTON_PRESS), FALSE); /* ignore double-click or any others */

	switch (event->button)
	{
	case LEFT_BUTTON:
		/* show/hidden man window */
		if (tray->status == SHOW)
		{
			tray->status = HIDDEN;
			//gtk_widget_hide_all (GTK_WIDGET (tray->window_main));
		}
		else
		{
			tray->status = SHOW;
			//gtk_widget_show_all (GTK_WIDGET (tray->window_main));
		}
		break;
	case MIDDLE_BUTTON:
		break;
	case RIGHT_BUTTON:
		/* popup menu */
		gtk_menu_popup (GTK_MENU(tray->menus), NULL, NULL, NULL, NULL,
				event->button, event->time);
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

GtkWidget *
load_image (int i)
{
	GtkWidget *image;
	GdkPixbuf *pixbuf=NULL;

	switch(i)
		{
		case 0:pixbuf =gdk_pixbuf_new_from_xpm_data((gchar **)connecting_xpm);break;
		case 1:pixbuf =gdk_pixbuf_new_from_xpm_data((gchar **)connecting1_xpm);break;
		case 2:pixbuf =gdk_pixbuf_new_from_xpm_data((gchar **)connecting2_xpm);break;
		}

	if (!pixbuf)
	{
		image = gtk_image_new_from_stock (GTK_STOCK_HOME,
						  GTK_ICON_SIZE_MENU);
	}
	else
	{
		image = gtk_image_new_from_pixbuf (pixbuf);
	}

	return image;
}

void
create_tray (tray_demo * tray)
{   j++;
	pix=(j==1)?0:((j%2==0)?1:2);
	image = load_image (pix);
		if(j>1)gtk_widget_destroy (GTK_WIDGET (tray_icon));
	tooltips = gtk_tooltips_new ();
	tray_icon = egg_tray_icon_new ("Tray icon demo");
	event_box = gtk_event_box_new ();	
	gtk_container_add (GTK_CONTAINER (tray_icon), event_box);
	g_signal_connect (G_OBJECT (event_box), "button-press-event",
			  G_CALLBACK (tray_button_press_event_cb), tray);
	gtk_tooltips_set_tip (GTK_TOOLTIPS(tooltips), event_box, _("MyNet v0.1"), NULL);
	gtk_container_add (GTK_CONTAINER (event_box), image);
	gtk_widget_show_all (GTK_WIDGET (tray_icon));
		return;
}
