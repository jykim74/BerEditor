#include "mac_sparkle_support.h"

#ifdef _AUTO_UPDATE

#import "SUUpdater.h"

void SparkleHelper::checkForUpdate()
{
    // [[SUUpdater sharedUpdater] checkForUpdatesInBackground];
    [[SUUpdater sharedUpdater] checkForUpdates:nil];
}

void SparkleHelper::setAutoUpdateEnabled(bool enabled)
{
    [[SUUpdater sharedUpdater] setAutomaticallyChecksForUpdates: enabled];
    // [[SUUpdater sharedUpdater] setAutomaticallyDownloadsUpdates: enabled];
}

void SparkleHelper::setFeedURL(const char* url)
{
    NSString *nsstr = [NSString stringWithCString:url
                                  encoding:NSUTF8StringEncoding];
    NSURL *feedURL = [NSURL URLWithString:nsstr];
    [[SUUpdater sharedUpdater] setFeedURL: feedURL];
}

bool SparkleHelper::autoUpdateEnabled() {
    return [[SUUpdater sharedUpdater] automaticallyChecksForUpdates];
}

#endif
