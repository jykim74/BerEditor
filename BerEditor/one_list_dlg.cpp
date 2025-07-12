#include "one_list_dlg.h"
#include "ber_applet.h"
#include "common.h"

OneListDlg::OneListDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);
    initUI();

    connect( mCloseBtn, SIGNAL(clicked()), this, SLOT(close()));
    connect( mAddBtn, SIGNAL(clicked()), this, SLOT(clickAdd()));
    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mClearBtn, SIGNAL(clicked()), this, SLOT(clickClear()));


#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

OneListDlg::~OneListDlg()
{

}

void OneListDlg::initUI()
{

}

void OneListDlg::setName( const QString strName )
{
    mNameList->clear();
    mNameLabel->setText( strName );
}

void OneListDlg::addName( const QString strName )
{
    QStringList listName = strName.split("#");

    for( int i = 0; i < listName.size(); i++ )
    {
        QString strOne = listName.at(i);
        mNameList->addItem( strOne );
    }
}

void OneListDlg::clickOK()
{
    accept();
}

const QStringList OneListDlg::getList()
{
    QStringList strList;

    int nCount = mNameList->count();

    for( int i = 0; i < nCount; i++ )
    {
        strList.append( mNameList->item(i)->text() );
    }

    return strList;
}

const QString OneListDlg::getListString()
{
    QString strList;

    int nCount = mNameList->count();

    for( int i = 0; i < nCount; i++ )
    {
        if( i != 0 ) strList += "#";

        strList += mNameList->item(i)->text();
    }

    return strList;
}

void OneListDlg::clickAdd()
{
    QString strName = mNameText->text();
    QString strLabel = mNameLabel->text();

    if( strName.length() < 1 )
    {
        berApplet->warningBox( tr( "Enter a %1" ).arg( strLabel), this );
        mNameText->setFocus();
        return;
    }

    mNameList->addItem( strName );
    mNameText->clear();
}

void OneListDlg::clickClear()
{
    mNameList->clear();
}
