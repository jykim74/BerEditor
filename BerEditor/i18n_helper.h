/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef I18N_HELPER_H
#define I18N_HELPER_H

#include <QList>
#include <QLocale>
#include <QStringList>
#include <QScopedPointer>

class QTranslator;


class I18NHelper
{
public:
    static I18NHelper* getInstance() {
        if( !instance_ ) {
            static I18NHelper i18n;
            instance_ = &i18n;
        }

        return instance_;
    }

    void init();

    QStringList getLanguages() {
        QStringList languages;
        Q_FOREACH( const QLocale& locale, getInstalledLocales() )
        {
            languages.push_back( QString("%1 - %2").arg(QLocale::languageToString(locale.language()))
                                 .arg(QLocale::countryToString(locale.country())));
        }

        languages.front() = "-- System --";
        return languages;
    }

    int preferredLanguage();
    void setPreferredLanguage(int langIndex);

private:
    I18NHelper();
    ~I18NHelper();
    I18NHelper(const I18NHelper&);

    const QList<QLocale> &getInstalledLocales();
    bool setLanguage( int langIndex );
    QScopedPointer<QTranslator> qt_translator_;
    QScopedPointer<QTranslator> my_translator_;

    static I18NHelper *instance_;
};

#endif // I18N_HELPER_H
