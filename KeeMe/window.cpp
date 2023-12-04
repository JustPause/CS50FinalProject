#include "window.h"
#include "./ui_window.h"

Window::Window(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

Window::~Window()
{
    delete ui;
}

std::string thePassword;

void Window::on_lineEdit_textChanged(const QString &arg1)
{
    thePassword =  arg1.toUtf8().data();

}

void Window::on_pushButton_clicked()
{
    qDebug("%s\n",thePassword.data());
}

