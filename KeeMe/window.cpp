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


void Window::on_lineEdit_textChanged(const QString &arg1)
{
    qDebug("%s\n", arg1.toUtf8().data());
}

