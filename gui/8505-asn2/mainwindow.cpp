#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QFileDialog>
#include <QProcess>

#include <string>

static QString tool_path{"8505-ass2"};

//check for if the cli is actually runable
//thanks to Gerhard Stein for the idea https://stackoverflow.com/a/51041497

/*
 * function:
 *    cli_avalible
 *
 * return:
 *    bool
 *
 * parameters:
 *    void
 *
 * notes:
 *    checks to see if the cli can be found
 *
 * */

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

/*
 * function:
 *    on_pushButtonClear_clicked
 *
 * return:
 *    void
 *
 * parameters:
 *    void
 *
 * notes:
 *    clears out the messages window
 *
 * */

void MainWindow::on_pushButtonClear_clicked() {
    ui->textBrowserMessages->setText({});
}

/*
 * function:
 *    append_message
 *
 * return:
 *    QString message
 *
 * parameters:
 *    void
 *
 * notes:
 *    adds message to the message window
 *
 * */
void MainWindow::append_message(QString st) {
    ui->textBrowserMessages->append(st);
}


/*
 * function:
 *    exec
 *
 * return:
 *    QString result
 *
 * parameters:
 *    QStringList args the args to pass the cli
 *
 * notes:
 *    runs the cli tool with the specifified args
 *
 * */

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

/*
 * function:
 *    MainWindow
 *
 * notes:
 *    initializes the main window
 *
 * */
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow) {
    ui->setupUi(this);
}

/*
 * function:
 *    ~MainWindow
 *
 * notes:
 *    cleans up the main window
 *
 * */
MainWindow::~MainWindow() {
    delete ui;
}

/*
 * function:
 *    bit_pos
 *
 * return:
 *    QString result
 *
 * parameters:
 *    void
 *
 * notes:
 *    finds the slected bit pos and returns string of it
 *
 * */
QString MainWindow::bit_pos() {
    if (ui->buttonGroupBit->checkedButton() == ui->radioButton0)
        return "0";
    if (ui->buttonGroupBit->checkedButton() == ui->radioButton1)
        return "1";
    if (ui->buttonGroupBit->checkedButton() == ui->radioButton2)
        return "2";
    if (ui->buttonGroupBit->checkedButton() == ui->radioButton3)
        return "3";
    if (ui->buttonGroupBit->checkedButton() == ui->radioButton4)
        return "4";
    if (ui->buttonGroupBit->checkedButton() == ui->radioButton5)
        return "5";
    if (ui->buttonGroupBit->checkedButton() == ui->radioButton6)
        return "6";
    return "7";
}

/*
 * function:
 *    on_pushButtonDecrypt_clicked
 *
 * return:
 *    void
 *
 * parameters:
 *    void
 *
 * notes:
 *    attempts to run decryption
 *
 * */
void MainWindow::on_pushButtonDecrypt_clicked() {
    if (ui->lineEditcf->text().length() == 0 || ui->lineEditout->text().length() == 0) {
        append_message("please select files before attempting decrypting");
        return;
    }

    if (!cli_avalible()) {
        append_message("could not find cli tool, please select it");
        return;
    }

    QStringList args;
    args << "-i" << ui->lineEditcf->text() << "-f" << ui->lineEditout->text() << "-p" << ui->lineEditPassword->text() << "-d" << "-s" << bit_pos();
    if (ui->buttonGroupEnc->checkedButton() == ui->radioButtonAES) {
        args << "-a";
    }
    append_message("running: " + tool_path + " "	+ args.join(" "));
    append_message(exec(args));
    append_message("finished");
}

/*
 * function:
 *    on_pushButtonEncrypt_clicked
 *
 * return:
 *    void
 *
 * parameters:
 *    void
 *
 * notes:
 *    attempts to run encryption
 *
 * */
void MainWindow::on_pushButtonEncrypt_clicked() {
    if (ui->lineEditcf->text().length() == 0 || ui->lineEditout->text().length() == 0 || ui->lineEditin->text().length() == 0) {
        append_message("please select files before attempting encrypting");
        return;
    }

    if (!cli_avalible()) {
        append_message("could not find cli tool, please select it");
        return;
    }

    QStringList args;
    args << "-i" << ui->lineEditcf->text() << "-o" << ui->lineEditout->text() << "-f" << ui->lineEditin->text() << "-p" << ui->lineEditPassword->text() << "-e" << "-s" << bit_pos();
    if (ui->buttonGroupEnc->checkedButton() == ui->radioButtonAES) {
        args << "-a";
    }
    append_message("running: " + tool_path + " "	+ args.join(" "));
    append_message(exec(args));
    append_message("finished");
}

/*
 * function:
 *    on_pushButtonTool_clicked
 *
 * return:
 *    void
 *
 * parameters:
 *    void
 *
 * notes:
 *    opens dialog to find tool
 *
 * */
void MainWindow::on_pushButtonTool_clicked() {
    QString mesg;
    tool_path = QFileDialog::getOpenFileName(nullptr, "Tool", ".");
    mesg = "Tool Selected: " + tool_path;

    append_message(mesg);
}

/*
 * function:
 *    on_pushButtonIn_clicked
 *
 * return:
 *    void
 *
 * parameters:
 *    void
 *
 * notes:
 *    opens dialog to find input file
 *
 * */
void MainWindow::on_pushButtonIn_clicked() {
    QString mesg, in_path;
    in_path = QFileDialog::getOpenFileName(nullptr, "Input File", ".");
    mesg = "Input File Opened: " + in_path;

    ui->lineEditin->setText(in_path);

    append_message(mesg);
}

/*
 * function:
 *    on_pushButtonOut_clicked
 *
 * return:
 *    void
 *
 * parameters:
 *    void
 *
 * notes:
 *    opens dialog to find output file
 *
 * */
void MainWindow::on_pushButtonOut_clicked() {
    QString mesg, out_path;
    out_path = QFileDialog::getSaveFileName(nullptr, "Output File", ".");
    mesg = "Output File Opened: " + out_path;

    ui->lineEditout->setText(out_path);

    append_message(mesg);
}

/*
 * function:
 *    on_pushButtonCF_clicked
 *
 * return:
 *    void
 *
 * parameters:
 *    void
 *
 * notes:
 *    opens dialog to find carrier file
 *
 * */
void MainWindow::on_pushButtonCF_clicked() {
    QString mesg, cf_path, filter{"PNG (*.png);;BMP (*.bmp))"};
    cf_path = QFileDialog::getOpenFileName(nullptr, "Carrier File", ".", filter, &filter);
    mesg = "Carrier File Opened: " + cf_path;

    ui->lineEditcf->setText(cf_path);

    ui->labelImage->setPixmap(QPixmap{cf_path});
    ui->labelImage->setText("");

    append_message(mesg);
}
