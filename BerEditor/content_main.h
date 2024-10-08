#ifndef CONTENT_MAIN_H
#define CONTENT_MAIN_H

#include <QMainWindow>
#include "ui_content_main.h"

namespace Ui {
class ContentMain;
}

class ContentMain : public QMainWindow, public Ui::ContentMain
{
    Q_OBJECT

public:
    explicit ContentMain(QWidget *parent = nullptr);
    ~ContentMain();

private:

};

#endif // CONTENT_MAIN_H
