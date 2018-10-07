#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QFileDialog>
#include <array>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

static QString cf_path, fth_path;

std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
            result += buffer.data();
    }
    return result;
}

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButtonCF_clicked()
{
    QFileDialog fd{};
    QString mesg;
    cf_path = fd.getOpenFileName();
    mesg = "Carrier File Opened: " + cf_path;

    ui->textBrowserMessages->setText(mesg);
}

void MainWindow::on_pushButtonFTH_clicked()
{
    QFileDialog fd{};
    QString mesg;
    fth_path = fd.getOpenFileName();
    mesg = "Combine File Opened: " + fth_path;

    ui->textBrowserMessages->setText(mesg);
}

void MainWindow::on_pushButtonExtract_clicked()
{

}

void MainWindow::on_pushButtonHide_clicked()
{
    if (cf_path.length() == 0 || fth_path.length() == 0) {
        ui->textBrowserMessages->setText("please select files before attempting hiding");
        return;
    }
    std::string result = exec(("8505-ass2 -i '" + cf_path.toStdString() + "' -o '"+ fth_path.toStdString() + "'").c_str());
    ui->textBrowserMessages->setText(QString::fromStdString(result));
}
