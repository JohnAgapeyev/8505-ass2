#include "mainwindow.h"
#include <QApplication>


/*
 * function:
 *    main
 *
 * return:
 *    int status code of the program
 *
 * parameters:
 *    int argc total arguments
 *    char *argv[] arguments passed
 *
 * notes:
 *    runs the program, initializing the window
 *
 * */

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
