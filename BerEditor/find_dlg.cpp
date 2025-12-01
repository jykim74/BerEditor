#include "find_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "common.h"
#include "settings_mgr.h"

#include "js_pki.h"
#include "js_kms.h"
#include "js_pki_tools.h"

static const QStringList kClassList = { "Universal", "Application", "Content-Specific", "Private" };

static const QStringList kTTLVTypeList = { "None", "Structure", "Integer", "LongInteger",
                                   "BigInteger", "Enumeration", "Boolean", "TextString",
                                   "ByteString", "DateTime", "Interval", "DateTimeExtented" };

static const QStringList kBerValueType = { "String", "Hex", "Decimal", "OID" };
static const QStringList kTTLVValueType = { "String", "Hex", "Number" };

FindDlg::FindDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    connect( mHeadCheck, SIGNAL(clicked()), this, SLOT(checkHeader()));
    connect( mValueTypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeValueType()));

    connect( mBER_ClassCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeBER_Class(int)));
    connect( mBER_TagCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeBER_Tag()));
    connect( mBER_ConstructedCheck, SIGNAL(clicked()), this, SLOT(checkBER_Constructed()));
    connect( mBER_TagIDText, SIGNAL(textChanged(QString)), this, SLOT(changeBER_TagID()));

    connect( mTTLV_TagText, SIGNAL(textChanged(QString)), this, SLOT(changeTTLV_Tag(QString)));
    connect( mTTLV_TypeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(changeTTLV_Type()));

    connect( mPreviousBtn, SIGNAL(clicked()), this, SLOT(clickPrevious()));
    connect( mNextBtn, SIGNAL(clicked()), this, SLOT(clickNext()));
    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mEditBtn, SIGNAL(clicked()), this, SLOT(clickEdit()));
    connect( mValueText, SIGNAL(textChanged(QString)), this, SLOT(changeValue()));

    initUI();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);

    mBERTab->layout()->setSpacing(5);
    mBERTab->layout()->setMargin(5);
    mTTLVTab->layout()->setSpacing(5);
    mTTLVTab->layout()->setMargin(5);
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

    mTTLV_TagText->setPlaceholderText( "4200XX" );
    mTTLV_TypeCombo->addItems( kTTLVTypeList );

    mValueTypeCombo->addItems( kBerValueType );

    mBERGroup->setEnabled(false);
    mTTLVGroup->setEnabled(false);
}

void FindDlg::initialize()
{
    mValueTypeCombo->clear();

    if( berApplet->mainWindow()->isTTLV() == true )
    {
        mTitleLabel->setText( tr( "Find TTLV" ));
        mValueTypeCombo->addItems( kTTLVValueType );

        tabWidget->setTabEnabled(0, false);
        tabWidget->setTabEnabled(1, true);
        tabWidget->setCurrentIndex(1);
    }
    else
    {
        mTitleLabel->setText( tr( "Find BER" ));
        mValueTypeCombo->addItems( kBerValueType );

        tabWidget->setTabEnabled(0, true);
        tabWidget->setTabEnabled(1, false);
        tabWidget->setCurrentIndex(0);
    }
}

void FindDlg::showEvent(QShowEvent *event)
{
    initialize();
}


void FindDlg::checkHeader()
{
    bool bVal = mHeadCheck->isChecked();

    mBERGroup->setEnabled(bVal);
    mTTLVGroup->setEnabled(bVal);
}

void FindDlg::getValueBIN( BIN *pBin )
{
    QString strType = mValueTypeCombo->currentText();
    QString strValue = mValueText->text();

    if( strType == "String" )
    {
        getBINFromString( pBin, DATA_STRING, strValue );
    }
    else if( strType == "Hex" )
    {
        getBINFromString( pBin, DATA_HEX, strValue );
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
        int nLeft = 4 - binTmp.nLen % 4;

        if( nLeft > 0 ) JS_BIN_setChar(pBin, 0x00, nLeft );
        JS_BIN_appendBin( pBin, &binTmp );
        JS_BIN_reset( &binTmp );
    }
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
    BIN binValue = {0,0};
    BerModel* model = berApplet->mainWindow()->berModel();
    BerTreeView *tree = berApplet->mainWindow()->berTree();
    BerItem *pCurItem = tree->currentItem();

    getValueBIN( &binValue );

    if( mHeadCheck->isChecked() == true )
    {
        BYTE cTag = mBER_HeaderText->text().toInt( nullptr, 16 );
        pCurItem = (BerItem *)model->findNextItemByValue( pCurItem, cTag, &binValue, mMatchedCheck->isChecked() );
    }
    else
    {
        pCurItem = (BerItem *)model->findNextItemByValue( pCurItem, &binValue, mMatchedCheck->isChecked() );
    }

    if( pCurItem )
    {
        QModelIndex fi = pCurItem->index();
        tree->clicked( fi );
        tree->setCurrentIndex( fi );
        model->selectValue( pCurItem, &binValue, berApplet->settingsMgr()->showPartOnly() );
    }
    else
    {
        berApplet->warningBox( tr( "There is no node to find" ), this );
    }

    JS_BIN_reset( &binValue );
}

void FindDlg::findBER_Previous()
{
    BIN binValue = {0,0};
    BerModel* model = berApplet->mainWindow()->berModel();
    BerTreeView *tree = berApplet->mainWindow()->berTree();
    BerItem *pCurItem = tree->currentItem();

    getValueBIN( &binValue );

    if( mHeadCheck->isChecked() == true )
    {
        BYTE cTag = mBER_HeaderText->text().toInt( nullptr, 16 );
        pCurItem = (BerItem *)model->findPrevItemByValue( pCurItem, cTag, &binValue, mMatchedCheck->isChecked() );
    }
    else
    {
        pCurItem = (BerItem *)model->findPrevItemByValue( pCurItem, &binValue, mMatchedCheck->isChecked() );
    }

    if( pCurItem )
    {
        QModelIndex fi = pCurItem->index();
        tree->clicked( fi );
        tree->setCurrentIndex( fi );
        model->selectValue( pCurItem, &binValue, berApplet->settingsMgr()->showPartOnly() );
    }
    else
    {
        berApplet->warningBox( tr( "There is no node to find" ), this );
    }

    JS_BIN_reset( &binValue );
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
        makeTTLV_Header();
        return;
    }

    int nTag = text.toInt(nullptr, 16);
    QString strName = JS_KMS_tagName( nTag );
    mTTLV_TagNameText->setText( strName );

    makeTTLV_Header();
}

void FindDlg::changeValueType()
{
    QString strType = mValueTypeCombo->currentText();
    mValueText->clear();

    if( strType == "Hex" )
    {
        QRegExp regExp("^[0-9a-fA-F]*$");
        QRegExpValidator* regVal = new QRegExpValidator( regExp );
        mValueText->setValidator( regVal );
        mValueText->setPlaceholderText( tr("valid characters: %1").arg( kHexChars ));
    }
    else if( strType == "String" )
    {
        mValueText->setValidator( NULL );
        mValueText->setPlaceholderText( tr("all characters") );
    }
    else if( strType == "Decimal" )
    {
        QRegExp regExp("^[0-9-]*$");
        QRegExpValidator* regVal = new QRegExpValidator( regExp );
        mValueText->setValidator( regVal );
        mValueText->setPlaceholderText( tr("valid characters: %1").arg( kDecimalChars ));
    }
    else if( strType == "OID" )
    {
        QRegExp regExp("^[0-9.]*$");
        QRegExpValidator* regVal = new QRegExpValidator( regExp );
        mValueText->setValidator( regVal );
        mValueText->setPlaceholderText( tr("Object Identifier") );
    }
}

void FindDlg::changeValue()
{
    BIN binVal = {0,0};
    getValueBIN( &binVal );
    mValueHexText->setText( getHexString( &binVal ) );
    JS_BIN_reset( &binVal );
}

void FindDlg::makeTTLV_Header()
{
    QString strTag = mTTLV_TagText->text();
    if( strTag.length() < 6 )
    {
        mTTLV_HeaderText->clear();
        return;
    }

    QString strHeader = QString( "%1%2" )
                            .arg( strTag )
                            .arg( mTTLV_TypeCombo->currentIndex(), 2, 16, QLatin1Char('0') );

    mTTLV_HeaderText->setText( strHeader.toUpper() );
}

void FindDlg::findTTLV_Next()
{
    BIN binValue = {0,0};
    BIN binHeader = {0,0};
    TTLVTreeModel* model = berApplet->mainWindow()->ttlvModel();
    TTLVTreeView *tree = berApplet->mainWindow()->ttlvTree();
    TTLVTreeItem *pCurItem = tree->currentItem();

    getValueBIN( &binValue );

    if( mHeadCheck->isChecked() == true )
    {
        QString strHeader = mTTLV_HeaderText->text();
        JS_BIN_decodeHex( strHeader.toStdString().c_str(), &binHeader );
        pCurItem = (TTLVTreeItem *)model->findNextItemByValue( pCurItem, &binHeader, &binValue, mMatchedCheck->isChecked() );
        JS_BIN_reset( &binHeader );
    }
    else
    {
        pCurItem = (TTLVTreeItem *)model->findNextItemByValue( pCurItem, &binValue, mMatchedCheck->isChecked() );
    }

    if( pCurItem )
    {
        QModelIndex fi = pCurItem->index();
        tree->clicked( fi );
        tree->setCurrentIndex( fi );
        model->selectValue( pCurItem, &binValue, berApplet->settingsMgr()->showPartOnly() );
    }
    else
    {
        berApplet->warningBox( tr( "There is no node to find" ), this );
    }

    JS_BIN_reset( &binValue );
}

void FindDlg::findTTLV_Previous()
{
    BIN binValue = {0,0};
    BIN binHeader = {0,0};
    TTLVTreeModel* model = berApplet->mainWindow()->ttlvModel();
    TTLVTreeView *tree = berApplet->mainWindow()->ttlvTree();
    TTLVTreeItem *pCurItem = tree->currentItem();

    getValueBIN( &binValue );

    if( mHeadCheck->isChecked() == true )
    {
        QString strHeader = mTTLV_HeaderText->text();
        JS_BIN_decodeHex( strHeader.toStdString().c_str(), &binHeader );
        pCurItem = (TTLVTreeItem *)model->findPrevItemByValue( pCurItem, &binHeader, &binValue, mMatchedCheck->isChecked() );
        JS_BIN_reset( &binHeader );
    }
    else
    {
        pCurItem = (TTLVTreeItem *)model->findPrevItemByValue( pCurItem, &binValue, mMatchedCheck->isChecked() );
    }

    if( pCurItem )
    {
        QModelIndex fi = pCurItem->index();
        tree->clicked( fi );
        tree->setCurrentIndex( fi );
        model->selectValue( pCurItem, &binValue, berApplet->settingsMgr()->showPartOnly() );
    }
    else
    {
        berApplet->warningBox( tr( "There is no node to find" ), this );
    }

    JS_BIN_reset( &binValue );
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

void FindDlg::clickEdit()
{
    if( berApplet->mainWindow()->isTTLV() )
    {
        TTLVTreeView* tree = berApplet->mainWindow()->ttlvTree();
        tree->EditItem();
    }
    else
    {
        BerTreeView *tree = berApplet->mainWindow()->berTree();
        tree->EditValue();
    }
}
