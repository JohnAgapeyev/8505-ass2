#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QFileDialog>
#include <QProcess>

#include <string>

static QString cf_path, in_path, out_path, tool_path{"8505-ass2"}, pass;

//check for if the cli is actually runable
//thanks to Gerhard Stein for the idea https://stackoverflow.com/a/51041497
bool cli_avalible() {
    QProcess findProcess;
    QStringList arguments;
    arguments << tool_path;
    findProcess.start("which", arguments);
    findProcess.setReadChannel(QProcess::ProcessChannel::StandardOutput);

    if(!findProcess.waitForFinished()) {
        return false; // Not found or which does not work
    }

    QString retStr(findProcess.readAll());

    retStr = retStr.trimmed();

    QFile file(retStr);
    QFileInfo check_file(file);

    if (check_file.exists() && check_file.isFile())	{
        return true; // Found!
    } else {
        return false; // Not found!
    }
}

void MainWindow::append_message(QString st) {
    ui->textBrowserMessages->append("\n" + st);
}

QString exec(QStringList args) {
    QProcess findProcess;
    findProcess.start(tool_path, args);
    findProcess.setReadChannel(QProcess::ProcessChannel::StandardOutput);

    if(!findProcess.waitForFinished()) {
        return ""; // Not found or which does not work
    }

    QString retStr(findProcess.readAll());

    retStr = retStr.trimmed();
    return retStr;
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

void MainWindow::on_pushButtonDecrypt_clicked()
{
    if (cf_path.length() == 0 || out_path.length() == 0) {
        ui->textBrowserMessages->setText("please select files before attempting decrypting");
        return;
    }

    if (!cli_avalible()) {
        ui->textBrowserMessages->setText("could not find cli tool, please select it");
        return;
    }

    QStringList args;
    args << "-i" << cf_path << "-o" << out_path << "-p" << ui->lineEditPassword->text() << "-d";
    if (ui->buttonGroupEnc->checkedButton() == ui->radioButtonAES) {
        args << "-a";
    }
    append_message("running:" + tool_path + args.join(" "));
    append_message(exec(args));
}

void MainWindow::on_pushButtonEncrypt_clicked()
{
    if (cf_path.length() == 0 || in_path.length() == 0 || out_path.length() == 0) {
        ui->textBrowserMessages->setText("please select files before attempting encrypting");
        return;
    }

    if (!cli_avalible()) {
        ui->textBrowserMessages->setText("could not find cli tool, please select it");
        return;
    }

    QStringList args;
    args << "-i" << cf_path << "-o" << out_path << "-f" << in_path << "-p" << ui->lineEditPassword->text() << "-e";
    if (ui->buttonGroupEnc->checkedButton() == ui->radioButtonAES) {
        args << "-a";
    }
    append_message("running:" + tool_path + args.join(" "));
    append_message(exec(args));
}

void MainWindow::on_pushButtonClear_clicked()
{
    ui->textBrowserMessages->setText({});
}

void MainWindow::on_pushButtonTool_clicked()
{
    QString mesg;
    tool_path = QFileDialog::getOpenFileName(0, "Tool", ".");
    mesg = "Tool Selected: " + tool_path;

    append_message(mesg);
}

void MainWindow::on_pushButtonIn_clicked()
{
    QString mesg;
    in_path = QFileDialog::getOpenFileName(0, "Input File", ".");
    mesg = "Input File Opened: " + in_path;

    append_message(mesg);
}

void MainWindow::on_pushButtonOut_clicked()
{
    QString mesg;
    out_path = QFileDialog::getSaveFileName(0, "Output File", ".");
    mesg = "Output File Opened: " + out_path;

    append_message(mesg);
}

void MainWindow::on_pushButtonCF_clicked()
{
    QString mesg;
    cf_path = QFileDialog::getOpenFileName(0, "Carrier File", ".", "*.png;*.bmp");
    mesg = "Carrier File Opened: " + cf_path;

    ui->textBrowserMessages->setText(mesg);
}
