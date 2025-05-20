#ifndef FIND_DLG_H
#define FIND_DLG_H

#include <QDialog>
#include "ui_find_dlg.h"
#include "ber_item.h"
#include "ttlv_tree_item.h"

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
    void checkHeader();

    void clickPrevious();
    void clickNext();
    void clickEdit();

    void checkBER_Constructed();
    void changeBER_Class( int index );
    void changeBER_Tag();
    void changeBER_TagID();

    void changeTTLV_Type();
    void changeTTLV_Tag( const QString text );

    void changeValueType();

private:
    void initUI();
    void initialize();

    void makeBER_Header();
    void findBER_Next();
    void findBER_Previous();

    void makeTTLV_Header();
    void findTTLV_Next();
    void findTTLV_Previous();

    void getValueBIN( BIN *pBin );
    bool isBerFind( BerItem *pItem );
    bool isTTLVFind( TTLVTreeItem *pItem );
    void setBerCondition();

    void setTTLVCondition();

    BerItem* findBerItem( BerItem *pItem, const BerItem *pSelItem );
    BerItem* getFoundBerItem( BerItem *pSelItem );

    TTLVTreeItem* findTTLVItem( TTLVTreeItem *pItem, const TTLVTreeItem *pSelItem  );
    TTLVTreeItem* getFoundTTLVItem( TTLVTreeItem *pSelItem );

private:
    int col_;
    int row_;
    QModelIndexList find_list_;

    QString last_head_;
    BIN last_value_;
    int last_level_;
};

#endif // FIND_DLG_H
