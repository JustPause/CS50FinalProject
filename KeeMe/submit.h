#ifndef SUBMIT_H
#define SUBMIT_H

#include <QObject>

class submit : public QObject
{
    Q_OBJECT
public:
    explicit submit(QObject *parent = nullptr);

signals:
};

#endif // SUBMIT_H
