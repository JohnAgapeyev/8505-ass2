#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_pushButtonCF_clicked();

    void on_pushButtonTool_clicked();

    void on_pushButtonClear_clicked();

    void on_pushButtonIn_clicked();

    void on_pushButtonOut_clicked();

    void on_pushButtonEncrypt_clicked();

    void on_pushButtonDecrypt_clicked();

private:
    void append_message(QString st);
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
