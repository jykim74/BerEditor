#ifndef BER_COMPARE_DLG_H
#define BER_COMPARE_DLG_H

#include <QDialog>
#include "ui_ber_compare_dlg.h"
#include "ber_model.h"
#include "js_bin.h"
#include "comp_model.h"

enum {
    BER_IS_SAME = 0,
    BER_TAG_DIFF,
    BER_HEAD_DIFF,
    BER_DEPTH_DIFF,
    BER_VALUE_DIFF,
    BER_NOT_SAME
};

namespace Ui {
class BERCompareDlg;
}

class BERCompareDlg : public QDialog, public Ui::BERCompareDlg
{
    Q_OBJECT

public:
    explicit BERCompareDlg(QWidget *parent = nullptr);
    ~BERCompareDlg();

private slots:
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);

    void clickFindA();
    void clickFindB();
    void clickDecodeA();
    void clickDecodeB();
    void clickClear();
    void clickCompare();

    void clickNodeA();
    void clickNodeB();

public slots:


private:
    void initUI();
    void initialize();

    int compare( BerItem *pA, BerItem *pB );
    void logA( const QString strLog, QColor cr );
    void logB( const QString strLog, QColor cr );

    CompModel* modelA_ = nullptr;
    CompModel* modelB_ = nullptr;
};

#endif // BER_COMPARE_DLG_H
