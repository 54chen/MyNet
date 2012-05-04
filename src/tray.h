/***************************************************************************
 *            tray.h
 *
 *  Fri Oct 13 15:55:26 2006
 *  Copyright  2006  User
 *  Email
 ****************************************************************************/
#ifndef _TRAY_DEMO_H
#define _TRAY_DEMO_H

G_BEGIN_DECLS


/* main window status */
enum
{
	SHOW = 0,
	HIDDEN
};

/* mouse button */
enum
{
	LEFT_BUTTON = 1,
	MIDDLE_BUTTON = 2,
	RIGHT_BUTTON = 3
};

typedef struct _tray_demo tray_demo;

struct _tray_demo
{
	GtkWidget *window_main;
	int status;

	GtkUIManager *ui;
	GtkActionGroup *actions;
	GtkWidget *menus;
};

/* tray icon display in notification arear */

void create_tray (tray_demo * tray);
gboolean tray_button_press_event_cb (GtkWidget * button,
				     GdkEventButton * event,
				     tray_demo * tray);

G_END_DECLS

#endif /* _TRAY_DEMO_H */
