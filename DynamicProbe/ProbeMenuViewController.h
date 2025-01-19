#import <UIKit/UIKit.h>
#import "DynamicProbeTweak.h"

@interface ProbeMenuViewController : UIViewController <UITableViewDelegate, UITableViewDataSource, UISearchBarDelegate, UIGestureRecognizerDelegate>
@property (nonatomic, strong) UITableView *menuTableView;
@property (nonatomic, strong, readonly) NSArray *menuSections;
@property (nonatomic, strong) NSArray *menuItems;
@property (nonatomic, assign) BOOL isInspecting;
@property (nonatomic, assign) BOOL isMeasuring;
@property (nonatomic, strong) NSMutableArray *capturedImages;
@property (nonatomic, strong) NSMutableDictionary *imageViewMap;
@property (nonatomic, strong, readonly) NSMutableArray *fridaScripts;
@property (nonatomic, strong, readonly) NSMutableDictionary *hookResults;

- (void)showFridaClassBrowser;
- (void)setupMethodTracing;
- (void)showMemorySearch;
- (void)showScriptInjection;
- (void)captureImage:(UIImage *)image fromView:(UIImageView *)imageView;
- (void)captureImage:(UIImage *)image withName:(NSString *)name;
- (void)showClassList:(NSArray *)classes;
@end