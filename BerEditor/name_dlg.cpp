#include "name_dlg.h"
#include "ber_applet.h"

NameDlg::NameDlg(QWidget *parent)
    : QDialog(parent)
{
    setupUi(this);

    connect( mOKBtn, SIGNAL(clicked()), this, SLOT(clickOK()));
    connect( mCancelBtn, SIGNAL(clicked()), this, SLOT(close()));

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
    mOKBtn->setDefault(true);
}

NameDlg::~NameDlg()
{

}

void NameDlg::setHeadLabel( const QString strHead )
{
    mHeadLabel->setText( strHead );
}

void NameDlg::setName( const QString strName )
{
    mNameText->setText( strName );
    mNameText->setSelection( 0, strName.length() );
}

void NameDlg::clickOK()
{
    QString strName = mNameText->text();

    if( strName.length() < 1 )
    {
        berApplet->warningBox( tr( "Please enter a name" ), this );
        mNameText->setFocus();
        return;
    }

    QDialog::accept();
}
