/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 5.11.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QGraphicsView>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralWidget;
    QGraphicsView *graphicsViewFTH;
    QGraphicsView *graphicsViewCF;
    QLabel *label;
    QLabel *label_2;
    QPushButton *pushButtonFTH;
    QPushButton *pushButtonCF;
    QPushButton *pushButton;
    QPushButton *pushButton_2;
    QGroupBox *groupBox;
    QLabel *label_4;
    QRadioButton *radioButtonAES;
    QRadioButton *radioButtonCHA;
    QLabel *label_3;
    QLineEdit *lineEdit;
    QStatusBar *statusBar;
    QMenuBar *menuBar;
    QButtonGroup *buttonGroupEnc;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QStringLiteral("MainWindow"));
        MainWindow->resize(991, 520);
        centralWidget = new QWidget(MainWindow);
        centralWidget->setObjectName(QStringLiteral("centralWidget"));
        graphicsViewFTH = new QGraphicsView(centralWidget);
        graphicsViewFTH->setObjectName(QStringLiteral("graphicsViewFTH"));
        graphicsViewFTH->setGeometry(QRect(10, 10, 451, 331));
        graphicsViewCF = new QGraphicsView(centralWidget);
        graphicsViewCF->setObjectName(QStringLiteral("graphicsViewCF"));
        graphicsViewCF->setGeometry(QRect(530, 10, 451, 331));
        label = new QLabel(centralWidget);
        label->setObjectName(QStringLiteral("label"));
        label->setGeometry(QRect(530, 350, 91, 20));
        label_2 = new QLabel(centralWidget);
        label_2->setObjectName(QStringLiteral("label_2"));
        label_2->setGeometry(QRect(10, 350, 81, 20));
        pushButtonFTH = new QPushButton(centralWidget);
        pushButtonFTH->setObjectName(QStringLiteral("pushButtonFTH"));
        pushButtonFTH->setGeometry(QRect(620, 350, 80, 23));
        pushButtonCF = new QPushButton(centralWidget);
        pushButtonCF->setObjectName(QStringLiteral("pushButtonCF"));
        pushButtonCF->setGeometry(QRect(70, 350, 80, 23));
        pushButton = new QPushButton(centralWidget);
        pushButton->setObjectName(QStringLiteral("pushButton"));
        pushButton->setGeometry(QRect(470, 160, 51, 23));
        pushButton_2 = new QPushButton(centralWidget);
        pushButton_2->setObjectName(QStringLiteral("pushButton_2"));
        pushButton_2->setGeometry(QRect(470, 190, 51, 23));
        groupBox = new QGroupBox(centralWidget);
        groupBox->setObjectName(QStringLiteral("groupBox"));
        groupBox->setGeometry(QRect(10, 380, 341, 91));
        label_4 = new QLabel(groupBox);
        label_4->setObjectName(QStringLiteral("label_4"));
        label_4->setGeometry(QRect(10, 30, 81, 20));
        radioButtonAES = new QRadioButton(groupBox);
        buttonGroupEnc = new QButtonGroup(MainWindow);
        buttonGroupEnc->setObjectName(QStringLiteral("buttonGroupEnc"));
        buttonGroupEnc->addButton(radioButtonAES);
        radioButtonAES->setObjectName(QStringLiteral("radioButtonAES"));
        radioButtonAES->setGeometry(QRect(250, 30, 91, 21));
        radioButtonCHA = new QRadioButton(groupBox);
        buttonGroupEnc->addButton(radioButtonCHA);
        radioButtonCHA->setObjectName(QStringLiteral("radioButtonCHA"));
        radioButtonCHA->setGeometry(QRect(90, 30, 151, 21));
        radioButtonCHA->setChecked(true);
        label_3 = new QLabel(groupBox);
        label_3->setObjectName(QStringLiteral("label_3"));
        label_3->setGeometry(QRect(10, 60, 59, 20));
        lineEdit = new QLineEdit(groupBox);
        lineEdit->setObjectName(QStringLiteral("lineEdit"));
        lineEdit->setGeometry(QRect(80, 60, 113, 23));
        MainWindow->setCentralWidget(centralWidget);
        statusBar = new QStatusBar(MainWindow);
        statusBar->setObjectName(QStringLiteral("statusBar"));
        MainWindow->setStatusBar(statusBar);
        menuBar = new QMenuBar(MainWindow);
        menuBar->setObjectName(QStringLiteral("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 991, 20));
        MainWindow->setMenuBar(menuBar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QApplication::translate("MainWindow", "MainWindow", nullptr));
        label->setText(QApplication::translate("MainWindow", "Combine File", nullptr));
        label_2->setText(QApplication::translate("MainWindow", "Carrier", nullptr));
        pushButtonFTH->setText(QApplication::translate("MainWindow", "Select File", nullptr));
        pushButtonCF->setText(QApplication::translate("MainWindow", "Select File", nullptr));
        pushButton->setText(QApplication::translate("MainWindow", "Hide", nullptr));
        pushButton_2->setText(QApplication::translate("MainWindow", "Extract", nullptr));
        groupBox->setTitle(QApplication::translate("MainWindow", "Encryption", nullptr));
        label_4->setText(QApplication::translate("MainWindow", "Algorithm:", nullptr));
        radioButtonAES->setText(QApplication::translate("MainWindow", "AES-GCM", nullptr));
        radioButtonCHA->setText(QApplication::translate("MainWindow", "ChaCha20-Poly1305", nullptr));
        label_3->setText(QApplication::translate("MainWindow", "Password:", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
