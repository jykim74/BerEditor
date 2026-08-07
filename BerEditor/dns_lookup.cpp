#include "dns_lookup.h"

#include <QRandomGenerator>
#include <QDataStream>

DnsLookup::DnsLookup()
{
    id_ = QRandomGenerator::global()->generate();
}

QString DnsLookup::lastError() const
{
    return error_;
}

QByteArray DnsLookup::createQuery(const QString& domain)
{
    QByteArray packet;

    QDataStream out(&packet,QIODevice::WriteOnly);
    out.setByteOrder(QDataStream::BigEndian);

    out << id_;
    out << (quint16)0x0100;
    out << (quint16)1;
    out << (quint16)0;
    out << (quint16)0;
    out << (quint16)0;

    QStringList labels = domain.split('.');

    for(const QString& s : labels)
    {
        packet.append((char)s.length());
        packet.append(s.toUtf8());
    }

    packet.append(char(0));

    out << (quint16)16;     // TXT
    out << (quint16)1;      // IN

    return packet;
}

QString DnsLookup::readName(const QByteArray& data,
                               int& offset)
{
    QString name;

    bool jumped=false;
    int jumpOffset=0;

    while(true)
    {
        quint8 len=(quint8)data[offset];

        if(len==0)
        {
            offset++;
            break;
        }

        if((len&0xC0)==0xC0)
        {
            quint16 ptr=((len&0x3F)<<8)
            |(quint8)data[offset+1];

            if(!jumped)
                jumpOffset=offset+2;

            offset=ptr;
            jumped=true;
            continue;
        }

        offset++;

        if(!name.isEmpty())
            name+='.';
        name+=QString::fromUtf8(data.mid(offset,len));

        offset+=len;
    }

    if(jumped)
        offset=jumpOffset;

    return name;
}

bool DnsLookup::lookup(const QString& dnsServer,
                       int nPort,
                          const QString& domain,
                          QStringList& txtRecords,
                          int timeout)
{
    txtRecords.clear();
    error_.clear();

    QByteArray query=createQuery(domain);

    if(socket_.writeDatagram(query,
                              QHostAddress(dnsServer),
                              nPort )<0)
    {
        error_=socket_.errorString();
        return false;
    }

    if(!socket_.waitForReadyRead(timeout))
    {
        error_="DNS Timeout";
        return false;
    }

    QByteArray data;
    data.resize(socket_.pendingDatagramSize());

    socket_.readDatagram(data.data(),data.size());
    if(data.size()<12)
    {
        error_="Invalid DNS packet";
        return false;
    }

    int pos=0;

    auto read16=[&](quint16& v)
    {
        v=((quint8)data[pos]<<8)
        |(quint8)data[pos+1];
        pos+=2;
    };

    auto read32=[&](quint32& v)
    {
        v=((quint8)data[pos]<<24)
        |((quint8)data[pos+1]<<16)
            |((quint8)data[pos+2]<<8)
            |(quint8)data[pos+3];
        pos+=4;
    };

    quint16 id,flags,qd,an,ns,ar;

    read16(id);
    read16(flags);
    read16(qd);
    read16(an);
    read16(ns);
    read16(ar);

    if(id!=id_)
    {
        error_="Transaction ID mismatch";
        return false;
    }

    for(int i=0;i<qd;i++)
    {
        readName(data,pos);
        pos+=4;
    }

    for(int i=0;i<an;i++)
    {
        readName(data,pos);

        quint16 type,cls;
        quint32 ttl;
        quint16 rdlen;

        read16(type);
        read16(cls);
        read32(ttl);
        read16(rdlen);

        if(type==16)
        {
            int end=pos+rdlen;

            QString txt;

            while(pos<end)
            {
                quint8 len=(quint8)data[pos++];
                txt += QString::fromUtf8(data.mid(pos,len));
                pos+=len;
            }

            txtRecords.append(txt);
        }
        else
        {
            pos+=rdlen;
        }
    }

    return true;
}
