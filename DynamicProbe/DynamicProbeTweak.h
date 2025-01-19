#import <UIKit/UIKit.h>
@class ProbeMenuViewController;

@interface DynamicProbeTweak : NSObject {
    @public
    ProbeMenuViewController *_menuVC;
    UIWindow *_menuWindow;
}
+ (instancetype)sharedInstance;
- (void)showMenu;
- (void)hideMenu;
@property (nonatomic, readonly) BOOL isInspecting;
@property (nonatomic, strong) ProbeMenuViewController *menuVC;
@end 