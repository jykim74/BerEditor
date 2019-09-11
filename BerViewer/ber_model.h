#ifndef BER_MODEL_H
#define BER_MODEL_H

#include <QStandardItemModel>
#include "ber_item.h"
#include "js_bin.h"

class BerModel : public QStandardItemModel
{
    Q_OBJECT
public:
    BerModel( QObject *parent = 0 );

    int openFile( const QString& filePath );
    void setBer( const BIN *pBer );

    int parseTree();
    int parseBer( int offset, BerItem *pItem );
    BIN& getBer() { return binBer_; };

private:
    void initialize();
    int getItem( int offset, BerItem *pItem );

    BIN     binBer_;
};

#endif // BER_MODEL_H
