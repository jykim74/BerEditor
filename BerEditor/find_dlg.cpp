#include "find_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "common.h"

#include "js_pki.h"
#include "js_kms.h"
#include "js_pki_tools.h"

static const QStringList kClassList = { "Universal", "Application", "Content-Specific", "Private" };

static const QStringList kTTLVTypeList = { "None", "Structure", "Integer", "LongInteger",
                                   "BigInteger", "Enumeration", "Boolean", "TextString",
                                   "ByteString", "DateTime", "Interval", "DateTimeExtented" };

static const QStringList kLevelList = { "Any", "1", "2", "3", "4", "5", "6", "7", "8", "9" };

static const QStringList kBerValueType = { "String", "Hex", "Decimal", "OID", "Bit" };
static const QStringList kTTLVValueType = { "String", "Hex", "Number" };

FindDlg::FindDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mBER_ClassCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeBER_Class(int)));
    connect( mBER_TagCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeBER_Tag()));
    connect( mBER_ConstructedCheck, SIGNAL(clicked()), this, SLOT(checkBER_Constructed()));
    connect( mBER_TagIDText, SIGNAL(textChanged(QString)), this, SLOT(changeBER_TagID()));

    connect( mTTLV_TagText, SIGNAL(textChanged(QString)), this, SLOT(changeTTLV_Tag(QString)));
    connect( mTTLV_TypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeTTLV_Type()));

    connect( mPreviousBtn, SIGNAL(clicked()), this, SLOT(clickPrevious()));
    connect( mNextBtn, SIGNAL(clicked()), this, SLOT(clickNext()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));

    initUI();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());

    mNextBtn->setDefault(true);
    tabWidget->setCurrentIndex(0);
}

FindDlg::~FindDlg()
{

}

void FindDlg::initUI()
{
    mBER_ClassCombo->addItems( kClassList );
    mBER_TagCombo->addItem( "None" );

    int nPrimitiveCnt = JS_BER_getPrimitiveCount();

    for( int i = 0; i < nPrimitiveCnt; i++ )
    {
        const char *pName = JS_BER_getPrimitiveNameAt( i );
        mBER_TagCombo->addItem( pName );
    }

    mTTLV_TypeCombo->addItems( kTTLVTypeList );

//    mPreviousBtn->setEnabled( false );
    mLevelCombo->addItems( kLevelList );
    mValueTypeCombo->addItems( kBerValueType );
}

void FindDlg::initialize()
{
    col_ = 0;
    row_ = 0;
    find_list_.clear();
    mValueTypeCombo->clear();

    if( berApplet->mainWindow()->isTTLV() == true )
    {
        mTitleLabel->setText( tr( "Find TTLV" ));
        mValueTypeCombo->addItems( kTTLVValueType );

        tabWidget->setTabEnabled(0, false);
        tabWidget->setTabEnabled(1, true);
    }
    else
    {
        mTitleLabel->setText( tr( "Find BER" ));
        mValueTypeCombo->addItems( kBerValueType );

        tabWidget->setTabEnabled(0, true);
        tabWidget->setTabEnabled(1, false);
    }
}

void FindDlg::showEvent(QShowEvent *event)
{
    initialize();
}

void FindDlg::getValueBIN( BIN *pBin )
{
    QString strType = mValueTypeCombo->currentText();
    QString strValue = mValueText->text();

    if( strType == "String" )
    {
        JS_BIN_set( pBin, (unsigned char *)strValue.toStdString().c_str(), strValue.toUtf8().length() );
    }
    else if( strType == "Hex" )
    {
        JS_BIN_decodeHex( strValue.toStdString().c_str(), pBin );
    }
    else if( strType == "Decimal" )
    {
        JS_PKI_decimalToBin( strValue.toStdString().c_str(), pBin );
    }
    else if( strType == "Bit" )
    {
        int nLeft = 0;
        int nMod = strValue.length() % 8;
        if( nMod > 0 ) nLeft = 8 - nMod;

        BIN binVal = {0,0};

        if( nLeft > 0 ) strValue += QString( "%1" ).arg( '0', nLeft, QLatin1Char('0'));
        unsigned char cCh = nLeft;
        JS_BIN_setChar( pBin, cCh, 1 );

        JS_PKI_bitToBin( strValue.toStdString().c_str(), &binVal );
        JS_BIN_appendBin( pBin, &binVal );
        JS_BIN_reset( &binVal );
    }
    else if( strType == "OID" )
    {
        JS_PKI_getOIDValueFromString( strValue.toStdString().c_str(), pBin );
    }
    else if( strType == "Number" )
    {
        BIN binTmp = {0,0};
        JS_PKI_decimalToBin( strValue.toStdString().c_str(), &binTmp );
        int nLeft = 4 - pBin->nLen % 4;

        if( nLeft > 0 ) JS_BIN_setChar(pBin, 0x00, nLeft );
        JS_BIN_appendBin( pBin, &binTmp );
        JS_BIN_reset( &binTmp );
    }
}

void FindDlg::setBerCondition()
{
    BIN binVal = {0,0};

    QString strHeader = mBER_HeaderText->text();
    QString strValue;
    int nLevel = mLevelCombo->currentIndex();

    if( last_level_ != nLevel )
    {
        find_list_.clear();
        last_level_ = nLevel;
    }

    if( last_head_ != strHeader )
    {
        find_list_.clear();
        last_head_ = strHeader;
    }

    getValueBIN( &binVal );
    strValue = getHexString( &binVal );
    JS_BIN_reset( &binVal );

    if( last_value_ != strValue )
    {
        find_list_.clear();
        last_value_ = strValue;
    }
}

bool FindDlg::isBerFind( BerItem *pItem )
{
    QString strHeader = mBER_HeaderText->text();
    QString strValue = mValueText->text();
    int nLevel = mLevelCombo->currentIndex();

    QString strItemHeader = getHexString( pItem->GetHeader(), 1 );

    if( nLevel > 0 )
    {
        if( pItem->GetLevel() != nLevel )
            return false;
    }

    if( strHeader == strItemHeader )
    {
        BIN binVal = {0,0};
        BIN binItemVal = {0,0};

        BerModel* model = berApplet->mainWindow()->berModel();

        if( strValue.length() < 1 )
            return true;

        getValueBIN( &binVal );
        pItem->getValueBin( &model->getBER(), &binItemVal );

        if( JS_BIN_cmp( &binVal, &binItemVal ) == 0 )
        {
            JS_BIN_reset( &binVal );
            JS_BIN_reset( &binItemVal );

            return true;
        }

        JS_BIN_reset( &binVal );
        JS_BIN_reset( &binItemVal );
    }

    return false;
}

bool FindDlg::isTTLVFind( TTLVTreeItem *pItem )
{
    QString strHeader = mTTLV_HeaderText->text();
    QString strValue = mValueText->text();
    int nLevel = mLevelCombo->currentIndex();

    BIN binHeader = {0,0};
    pItem->getHeader( &binHeader );

    if( binHeader.nLen != 8 )
    {
        JS_BIN_reset( &binHeader );
        return false;
    }

    QString strItemHeader = getHexString( binHeader.pVal, 4 );
    JS_BIN_reset( &binHeader );

    if( nLevel > 0 )
    {
        if( pItem->getLevel() != nLevel )
            return false;
    }

    if( strHeader == strItemHeader )
    {
        BIN binVal = {0,0};
        BIN binItemVal = {0,0};

        TTLVTreeModel* model = berApplet->mainWindow()->ttlvModel();

        if( strValue.length() < 1 )
            return true;

        getValueBIN( &binVal );

        pItem->getValue( &model->getTTLV(), &binItemVal );

        if( JS_BIN_cmp( &binVal, &binItemVal ) == 0 )
        {
            JS_BIN_reset( &binVal );
            JS_BIN_reset( &binItemVal );

            return true;
        }

        JS_BIN_reset( &binVal );
        JS_BIN_reset( &binItemVal );
    }

    return false;
}

void FindDlg::makeBER_Header()
{
    unsigned char cTag = 0x00;
    unsigned char cPrimitive = 0x00;

    QString strClass = mBER_ClassCombo->currentText();


    if( strClass == "Universal" )
        cTag |= JS_UNIVERSAL;
    else if( strClass == "Application" )
        cTag |= JS_APPLICATION;
    else if( strClass == "Content-Specific" )
        cTag |= JS_CONTEXT;
    else if( strClass == "Private" )
        cTag |= JS_PRIVATE;

    if( mBER_ConstructedCheck->isChecked() )
    {
        cTag |= JS_CONSTRUCTED;
    }

    if( cTag & JS_CONTEXT )
    {
        unsigned char cNum = mBER_TagIDText->text().toInt( nullptr, 16 );
        if( cNum > 0x1F )
        {
            berApplet->warningBox( tr( "Invalid Number: %1").arg(cNum), this );
            return;
        }

        cTag |= cNum;
    }
    else
    {
        cPrimitive = JS_BER_getPrimitiveTag( mBER_TagCombo->currentText().toStdString().c_str() );
        cTag |= cPrimitive;
    }

    mBER_HeaderText->setText( getHexString( &cTag, 1) );
}

void FindDlg::checkBER_Constructed()
{
    makeBER_Header();
}

void FindDlg::changeBER_Class( int index )
{
    if( index == 2 )
    {
        mBER_TagCombo->setEnabled( false );
        mBER_TagIDText->setReadOnly( false );
        mBER_TagIDText->clear();
    }
    else
    {
        mBER_TagCombo->setEnabled(true);
        mBER_TagIDText->setReadOnly( true );
    }

    makeBER_Header();
}

void FindDlg::changeBER_Tag()
{
    unsigned char cPrimitive = 0x00;
    cPrimitive = JS_BER_getPrimitiveTag( mBER_TagCombo->currentText().toStdString().c_str() );

    if( cPrimitive == JS_SET || cPrimitive == JS_SEQUENCE )
        mBER_ConstructedCheck->setChecked( true );

    mBER_TagIDText->setText( QString( "%1" ).arg( cPrimitive, 2, 16, QLatin1Char('0')));
}

void FindDlg::changeBER_TagID()
{
    makeBER_Header();
}

void FindDlg::findBER_Next()
{
    BerTreeView *tree = berApplet->mainWindow()->berTree();
    BerModel* model = berApplet->mainWindow()->berModel();
    QModelIndex ri = model->index(0,0);

    BerItem* root = (BerItem *)model->itemFromIndex(ri);
    if( root == NULL )
    {
        berApplet->warningBox( tr( "There is no node to find" ), this );
        return;
    }

    setBerCondition();

    BerItem* curItem = (BerItem *)model->itemFromIndex( tree->currentIndex() );

    tree->expandAll();
    BerItem *findItem = NULL;

    if( curItem ) findItem = getFoundBerItem( curItem );

    if( findItem == NULL )
        findItem = findBerItem( root, curItem );

    if( findItem )
    {
        QModelIndex fi = findItem->index();

        tree->clicked( fi );
        tree->setCurrentIndex(fi);
    }
    else
    {
        berApplet->warningBox( tr( "There is no node to find" ), this );
        return;
    }

}

void FindDlg::findBER_Previous()
{
    BerTreeView *tree = berApplet->mainWindow()->berTree();
    BerModel* model = berApplet->mainWindow()->berModel();
    QModelIndex ri = tree->currentIndex();

    BerItem* item = (BerItem *)model->itemFromIndex( ri );

    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no node to find" ), this );
        return;
    }

    setBerCondition();

    bool bExist = false;

    for( int i = 1; i < find_list_.size(); i++ )
    {
        QModelIndex find_idx = find_list_.at(i);

        if( find_idx == ri )
        {
            ri = find_list_.at( i - 1 );
            bExist = true;
        }
    }

    if( bExist == true )
    {
        tree->expandAll();
        tree->clicked( ri );
        tree->setCurrentIndex(ri);
    }
    else
    {
        berApplet->warningBox( tr( "There is no node to find" ), this );
        return;
    }
}

void FindDlg::setTTLVCondition()
{
    BIN binVal = {0,0};

    QString strHeader = mTTLV_HeaderText->text();
    QString strValue;
    int nLevel = mLevelCombo->currentIndex();

    if( last_level_ != nLevel )
    {
        find_list_.clear();
        last_level_ = nLevel;
    }

    if( last_head_ != strHeader )
    {
        find_list_.clear();
        last_head_ = strHeader;
    }

    getValueBIN( &binVal );
    strValue = getHexString( &binVal );
    JS_BIN_reset( &binVal );

    if( last_value_ != strValue )
    {
        find_list_.clear();
        last_value_ = strValue;
    }
}

void FindDlg::changeTTLV_Type()
{
    makeTTLV_Header();
}

void FindDlg::changeTTLV_Tag( const QString text )
{
    if( text.length() < 6 )
    {
        mTTLV_TagNameText->clear();
        return;
    }

    int nTag = text.toInt(nullptr, 16);
    QString strName = JS_KMS_tagName( nTag );
    mTTLV_TagNameText->setText( strName );

    makeTTLV_Header();
}

void FindDlg::makeTTLV_Header()
{
    QString strTag = mTTLV_TagText->text();
    if( strTag.length() < 6 ) return;

    QString strHeader = QString( "%1%2" )
                            .arg( strTag )
                            .arg( mTTLV_TypeCombo->currentIndex(), 2, 16, QLatin1Char('0') );

    mTTLV_HeaderText->setText( strHeader.toUpper() );
}

void FindDlg::findTTLV_Next()
{
    TTLVTreeView* tree = berApplet->mainWindow()->ttlvTree();
    TTLVTreeModel* model = berApplet->mainWindow()->ttlvModel();

    QModelIndex ri = model->index(0,0);

    TTLVTreeItem* root = (TTLVTreeItem *)model->itemFromIndex(ri);
    if( root == NULL )
    {
        berApplet->warningBox( tr( "There is no node to find" ), this );
        return;
    }

    setTTLVCondition();
    TTLVTreeItem* curItem = (TTLVTreeItem *)model->itemFromIndex( tree->currentIndex() );

    tree->expandAll();
    TTLVTreeItem *findItem = NULL;

    if( curItem ) findItem = getFoundTTLVItem( curItem );

    if( findItem == NULL )
        findItem = findTTLVItem( root, curItem );

    if( findItem )
    {
        QModelIndex fi = findItem->index();

        tree->clicked( fi );
        tree->setCurrentIndex(fi);
    }
    else
    {
        berApplet->warningBox( tr( "There is no node to find" ), this );
        return;
    }

}

void FindDlg::findTTLV_Previous()
{
    TTLVTreeView* tree = berApplet->mainWindow()->ttlvTree();
    TTLVTreeModel* model = berApplet->mainWindow()->ttlvModel();
    QModelIndex ri = tree->currentIndex();

    TTLVTreeItem* item = (TTLVTreeItem *)model->itemFromIndex( ri );

    if( item == NULL )
    {
        berApplet->warningBox( tr( "There is no node to find" ), this );
        return;
    }

    setTTLVCondition();

    bool bExist = false;

    for( int i = 1; i < find_list_.size(); i++ )
    {
        QModelIndex find_idx = find_list_.at(i);

        if( find_idx == ri )
        {
            ri = find_list_.at( i - 1 );
            bExist = true;
        }
    }

    if( bExist == true )
    {
        tree->expandAll();
        tree->clicked( ri );
        tree->setCurrentIndex(ri);
    }
    else
    {
        berApplet->warningBox( tr( "There is no node to find" ), this );
        return;
    }
}

void FindDlg::clickPrevious()
{
    if( berApplet->mainWindow()->isTTLV() )
        findTTLV_Previous();
    else
        findBER_Previous();
}

void FindDlg::clickNext()
{
    if( berApplet->mainWindow()->isTTLV() )
        findTTLV_Next();
    else
        findBER_Next();
}

BerItem* FindDlg::getFoundBerItem( BerItem *pSelItem )
{
    if( pSelItem == NULL ) return nullptr;

    for( int i = 0; i < find_list_.size() - 1; i++ )
    {
        QModelIndex find_idx = find_list_.at(i);

        if( find_idx == pSelItem->index() )
        {
            BerModel* model = berApplet->mainWindow()->berModel();
            return (BerItem *)model->itemFromIndex( find_list_.at( i+1 ) );
        }
    }

    return NULL;
}

TTLVTreeItem* FindDlg::getFoundTTLVItem( TTLVTreeItem *pSelItem )
{
    if( pSelItem == NULL ) return nullptr;

    for( int i = 0; i < find_list_.size() - 1; i++ )
    {
        QModelIndex find_idx = find_list_.at(i);

        if( find_idx == pSelItem->index() )
        {
            TTLVTreeModel* model = berApplet->mainWindow()->ttlvModel();
            return (TTLVTreeItem *)model->itemFromIndex( find_list_.at( i+1 ) );
        }
    }

    return NULL;
}

BerItem* FindDlg::findBerItem( BerItem *pItem, const BerItem *pSelItem )
{
    if( pItem == NULL ) return NULL;

    if( isBerFind( pItem ) == true )
    {
        bool bExist = false;
        berApplet->log( QString( "Find: %1" ).arg( pItem->text() ));
        QModelIndex curIndex = pItem->index();

        for( int i = 0; i < find_list_.size(); i++ )
        {
            QModelIndex find_idx = find_list_.at(i);

            if( find_idx == curIndex )
                bExist = true;
        }

        if( bExist == false )
        {
            find_list_.append( curIndex );
            return pItem;
        }
    }


//    ber_list_.append( pItem );

    if( pItem->hasChildren() )
    {
        int i = 0;

        while( 1 )
        {
            BerItem* pChild = (BerItem *)pItem->child(i);
            if( pChild == NULL ) return NULL;

            BerItem* pFind = findBerItem( pChild, pSelItem );
            if( pFind ) return pFind;

            i++;
        }
    }

    return NULL;
}

TTLVTreeItem* FindDlg::findTTLVItem( TTLVTreeItem *pItem, const TTLVTreeItem *pSelItem )
{
    if( pItem == NULL ) return NULL;

    if( isTTLVFind( pItem ) == true )
    {
        bool bExist = false;
        berApplet->log( QString( "Find: %1" ).arg( pItem->text() ));
        QModelIndex curIndex = pItem->index();

        for( int i = 0; i < find_list_.size(); i++ )
        {
            QModelIndex find_idx = find_list_.at(i);

            if( find_idx == curIndex )
                bExist = true;
        }

        if( bExist == false )
        {
            find_list_.append( curIndex );
            return pItem;
        }
    }


    //    ber_list_.append( pItem );

    if( pItem->hasChildren() )
    {
        int i = 0;

        while( 1 )
        {
            TTLVTreeItem* pChild = (TTLVTreeItem *)pItem->child(i);
            if( pChild == NULL ) return NULL;

            TTLVTreeItem* pFind = findTTLVItem( pChild, pSelItem );
            if( pFind ) return pFind;

            i++;
        }
    }

    return NULL;
}
