/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include <QTranslator>
#include <QLibraryInfo>
#include <QApplication>
#include <QSettings>
#include <QDebug>

#include "i18n_helper.h"

namespace  {
const char* langs[] = {
    NULL,
    "en",
    "ko_KR",
    NULL
};

void saveCurrentLanguage( int langIndex ) {
    QSettings settings;

    settings.beginGroup( "Language" );
    settings.setValue( "current", QString(langs[langIndex]));
    settings.endGroup();
}

int loadCurrentLanguage() {
    QSettings settings;

    settings.beginGroup( "Language" );
    QString current = settings.value("current").toString();
    settings.endGroup();

    if( current.isEmpty() ) {
        return 0;
    }

    const char** pos = langs;
    while( *++pos != NULL ) {
        if( *pos == current )
            break;
    }

    return pos - langs;
}
}

I18NHelper *I18NHelper::instance_ = NULL;

I18NHelper::I18NHelper()
    : qt_translator_(new QTranslator),
      my_translator_(new QTranslator)
{

}

I18NHelper::~I18NHelper()
{

}

void I18NHelper::init()
{
    qApp->installTranslator( qt_translator_.data());
    qApp->installTranslator(my_translator_.data());

    int pos = preferredLanguage();

    if( langs[pos] == NULL )
        setLanguage(0);
    else {
        setLanguage(pos);
    }
}

int I18NHelper::preferredLanguage()
{
    return loadCurrentLanguage();
}

void I18NHelper::setPreferredLanguage(int langIndex) {
    const QList<QLocale> &locales = getInstalledLocales();

    if( langIndex < 0 || langIndex >= locales.size() )
        return;

    saveCurrentLanguage(langIndex);
}


bool I18NHelper::setLanguage(int langIndex) {
    const QList<QLocale> &locales = getInstalledLocales();

    if( langIndex < 0 || langIndex >= locales.size() )
        return false;

    const QLocale &locale = locales[langIndex];

#if defined (Q_OS_WIN32)
    qt_translator_->load( "qt_" + locale.name());
#else
    qt_translator_->load("qt_" + locale.name(), QLibraryInfo::location(QLibraryInfo::TranslationsPath));
#endif

    QString lang = QLocale::languageToString(locale.language());

    if( lang != "English" )
    {
        if( !my_translator_->load(locale, ":/i18n/bereditor_"))
        {
            my_translator_->load(QString(":/i18n/bereditor_%1.qm").arg(locale.name()));
        }
    }

    return true;
}

const QList<QLocale> &I18NHelper::getInstalledLocales() {
    static QList<QLocale> locales;

    if( locales.empty() ) {
        locales.push_back(QLocale::system());

        const char ** next = langs;

        while(*++next != NULL )
            locales.push_back(QLocale(*next));
    }

    return locales;
}
