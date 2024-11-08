#ifndef FIND_DLG_H
#define FIND_DLG_H

#include <QDialog>
#include "ui_find_dlg.h"

namespace Ui {
class FindDlg;
}

class FindDlg : public QDialog, public Ui::FindDlg
{
    Q_OBJECT

public:
    explicit FindDlg(QWidget *parent = nullptr);
    ~FindDlg();

private slots:
    void showEvent(QShowEvent *event);

    void clickPrevious();
    void clickNext();

    void checkBER_Constructed();
    void changeBER_Class( int index );
    void changeBER_Tag();
    void changeBER_TagID();

    void changeTTLV_Type();
    void changeTTLV_Tag( const QString text );

private:
    void initUI();
    void initialize();

    void makeBER_Header();
    void findBER_Next();
    void findBER_Previous();

    void makeTTLV_Header();
    void findTTLV_Next();
    void findTTLV_Previous();
};

#endif // FIND_DLG_H
