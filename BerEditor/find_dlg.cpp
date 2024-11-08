#include "find_dlg.h"
#include "mainwindow.h"
#include "ber_applet.h"
#include "ttlv_tree_item.h"
#include "common.h"

#include "js_kms.h"

static const QStringList kClassList = { "Universal", "Application", "Content-Specific", "Private" };

static const QStringList kTTLVTypeList = { "None", "Structure", "Integer", "LongInteger",
                                   "BigInteger", "Enumeration", "Boolean", "TextString",
                                   "ByteString", "DateTime", "Interval", "DateTimeExtented" };

static const QStringList kLevelList = { "Any", "1", "2", "3", "4", "5", "6", "7", "8" };

static const QStringList kValueType = { "String", "Hex", "Integer", "OID", "Binary" };

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

    mPreviousBtn->setEnabled( false );
    mLevelCombo->addItems( kLevelList );
    mLevelCombo->setEnabled( true );
    mValueTypeCombo->addItems( kValueType );
}

void FindDlg::initialize()
{
    if( berApplet->mainWindow()->isTTLV() == true )
    {
        mTitleLabel->setText( tr( "Find TTLV" ));

        tabWidget->setTabEnabled(0, false);
        tabWidget->setTabEnabled(1, true);
    }
    else
    {
        mTitleLabel->setText( tr( "Find BER" ));

        tabWidget->setTabEnabled(0, true);
        tabWidget->setTabEnabled(1, false);
    }
}

void FindDlg::showEvent(QShowEvent *event)
{
    initialize();
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

    QString strHeader = mBER_HeaderText->text();
    QString strValue = mValueText->text();
    int nLevel = mLevelCombo->currentIndex();

    BerItem* root = (BerItem *)model->itemFromIndex(ri);
    tree->clicked( ri );
    tree->setCurrentIndex(ri);
    berApplet->log( root->text() );
}

void FindDlg::findBER_Previous()
{
    BerTreeView *tree = berApplet->mainWindow()->berTree();
    BerModel* model = berApplet->mainWindow()->berModel();
    QModelIndex ri = model->index(0,0);

    QString strHeader = mBER_HeaderText->text();
    QString strValue = mValueText->text();
    int nLevel = mLevelCombo->currentIndex();

    BerItem* root = (BerItem *)model->itemFromIndex(ri);
    tree->clicked( ri );
    tree->setCurrentIndex(ri);
    berApplet->log( root->text() );
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

    QString strHeader = mTTLV_HeaderText->text();
    QString strValue = mValueText->text();
    int nLevel = mLevelCombo->currentIndex();

    TTLVTreeItem* root = (TTLVTreeItem *)model->itemFromIndex(ri);
    tree->clicked( ri );
    tree->setCurrentIndex(ri);
    berApplet->log( root->text() );
}

void FindDlg::findTTLV_Previous()
{
    TTLVTreeView* tree = berApplet->mainWindow()->ttlvTree();
    TTLVTreeModel* model = berApplet->mainWindow()->ttlvModel();

    QModelIndex ri = model->index(0,0);

    QString strHeader = mTTLV_HeaderText->text();
    QString strValue = mValueText->text();
    int nLevel = mLevelCombo->currentIndex();

    TTLVTreeItem* root = (TTLVTreeItem *)model->itemFromIndex(ri);
    tree->clicked( ri );
    tree->setCurrentIndex(ri);
    berApplet->log( root->text() );
}

void FindDlg::clickPrevious()
{
    if( berApplet->mainWindow()->isTTLV() )
        findBER_Previous();
    else
        findBER_Next();
}

void FindDlg::clickNext()
{
    if( berApplet->mainWindow()->isTTLV() )
        findTTLV_Next();
    else
        findBER_Next();
}
