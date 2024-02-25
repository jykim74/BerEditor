/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAC_SPARKLE_SUPPORT_H
#define MAC_SPARKLE_SUPPORT_H

class SparkleHelper {
public:
    static void checkForUpdate();
    static void setAutoUpdateEnabled(bool enabled);
    static bool autoUpdateEnabled();
    static void setFeedURL(const char* url);
};

#endif // MAC_SPARKLE_SUPPORT_H
