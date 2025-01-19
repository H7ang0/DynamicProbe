#ifdef DYLIB
#define IS_DYLIB_MODE 1
#else
#define IS_DYLIB_MODE 0
#endif

#import <UIKit/UIKit.h>
#import <AudioToolbox/AudioToolbox.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <spawn.h>
#import <sys/wait.h>
#import "ProbeMenuViewController.h"
#import "DynamicProbeTweak.h"

@interface DynamicProbeTweak ()
@property (nonatomic, strong) NSMutableDictionary *methodLogs;
@property (nonatomic, strong) NSMutableSet *monitoredClasses;
@end

@interface NSBundle (DynamicProbe)
- (void)setupFridaRuntime;
- (void)loadFridaScript:(NSString *)script;
- (void)fridaOutput:(NSNotification *)notification;
@end

@implementation DynamicProbeTweak

+ (instancetype)sharedInstance {
    static DynamicProbeTweak *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}

- (instancetype)init {
    if (self = [super init]) {
        _methodLogs = [NSMutableDictionary dictionary];
        _monitoredClasses = [NSMutableSet set];
    }
    return self;
}

- (void)showMenu {
    if (!_menuWindow) {
        CGFloat screenWidth = UIScreen.mainScreen.bounds.size.width;
        CGFloat screenHeight = UIScreen.mainScreen.bounds.size.height;
        
        _menuWindow = [[UIWindow alloc] initWithFrame:CGRectMake(screenWidth * 0.25, 0, 
                                                                screenWidth * 0.75, 
                                                                screenHeight)];
        _menuWindow.windowLevel = UIWindowLevelAlert + 1;
        _menuWindow.backgroundColor = [UIColor clearColor];
        _menuWindow.layer.shadowColor = [UIColor blackColor].CGColor;
        _menuWindow.layer.shadowOffset = CGSizeMake(-2, 0);
        _menuWindow.layer.shadowOpacity = 0.3;
        _menuWindow.layer.shadowRadius = 5.0;
        
        _menuVC = [[ProbeMenuViewController alloc] init];
        _menuWindow.rootViewController = _menuVC;
    }
    
    _menuWindow.hidden = NO;
    
    _menuWindow.transform = CGAffineTransformMakeTranslation(_menuWindow.bounds.size.width, 0);
    [UIView animateWithDuration:0.3 
                          delay:0 
         usingSpringWithDamping:0.8 
          initialSpringVelocity:0.5 
                        options:UIViewAnimationOptionCurveEaseOut 
                     animations:^{
        self->_menuWindow.transform = CGAffineTransformIdentity;
    } completion:nil];
}

- (void)hideMenu {
    [UIView animateWithDuration:0.25 animations:^{
        self->_menuWindow.transform = CGAffineTransformMakeTranslation(self->_menuWindow.bounds.size.width, 0);
    } completion:^(BOOL finished) {
        self->_menuWindow.hidden = YES;
        self->_menuWindow.transform = CGAffineTransformIdentity;
    }];
}

- (void)logMethodCall:(NSString *)className selector:(SEL)selector {
    NSString *key = [NSString stringWithFormat:@"%@_%@", className, NSStringFromSelector(selector)];
    NSNumber *count = self.methodLogs[key];
    self.methodLogs[key] = @(count.integerValue + 1);
}

- (BOOL)isInspecting {
    return _menuVC.isInspecting;
}

- (void)setup {
#if IS_DYLIB_MODE
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *mainBundleID = [[NSBundle mainBundle] bundleIdentifier];
        NSLog(@"[DynamicProbe] 正在注入到应用: %@", mainBundleID);
        [self setupRuntimePrivileges];
        [self initializeFrida];
    });
#endif
}

- (void)setupRuntimePrivileges {
#ifdef __arm64e__
    void *handle = dlopen("/usr/lib/libjailbreak.dylib", RTLD_LAZY);
    if (handle) {
        typedef void (*fix_entitle_prt_t)(pid_t pid, uint32_t what);
        fix_entitle_prt_t ptr = (fix_entitle_prt_t)dlsym(handle, "jb_oneshot_entitle_now");
        if (ptr) {
            ptr(getpid(), 0);
        }
        dlclose(handle);
    }
#endif
}

- (void)initializeFrida {
    NSString *fridaPath = [[NSBundle mainBundle] pathForResource:@"frida-gadget" ofType:@"dylib"];
    if (fridaPath) {
        void *handle = dlopen([fridaPath UTF8String], RTLD_LAZY);
        if (handle) {
            NSLog(@"[DynamicProbe] Frida 运行时加载成功");
        } else {
            NSLog(@"[DynamicProbe] Frida 运行时加载失败: %s", dlerror());
        }
    }
}

@end

%hook UIWindow

- (void)motionEnded:(UIEventSubtype)motion withEvent:(UIEvent *)event {
    if (motion == UIEventSubtypeMotionShake) {
        [[DynamicProbeTweak sharedInstance] showMenu];
        AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
    }
    %orig;
}

%end

%hook UIApplication

- (void)sendEvent:(UIEvent *)event {
    if (event.type == UIEventTypeTouches) {
        UITouch *touch = event.allTouches.anyObject;
        if (touch.phase == UITouchPhaseBegan) {
            CGPoint location = [touch locationInView:nil];
            if (![DynamicProbeTweak sharedInstance]->_menuWindow.hidden &&
                !CGRectContainsPoint([DynamicProbeTweak sharedInstance]->_menuWindow.frame, location)) {
                [[DynamicProbeTweak sharedInstance] hideMenu];
            }
        }
    }
    %orig;
}

- (void)didReceiveMemoryWarning {
    %orig;
    NSLog(@"[DynamicProbe] 收到内存警告");
}

%end

%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request 
                          completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    NSString *urlString = request.URL.absoluteString;
    NSLog(@"[DynamicProbe] 网络请求: %@", urlString);
    return %orig;
}

%end

%hook UIViewController

- (void)viewDidAppear:(BOOL)animated {
    %orig;
    NSString *className = NSStringFromClass([self class]);
    NSLog(@"[DynamicProbe] 页面显示: %@", className);
}

%end

%hook UIDevice

- (void)setBatteryMonitoringEnabled:(BOOL)enabled {
    %orig(YES);
}

%end

%hook AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    BOOL result = %orig;
    NSLog(@"[DynamicProbe] 应用启动完成");
    return result;
}

- (void)applicationWillResignActive:(UIApplication *)application {
    %orig;
    NSLog(@"[DynamicProbe] 应用即将进入后台");
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    %orig;
    NSLog(@"[DynamicProbe] 应用进入前台");
}

%end

%hook NSBundle

- (NSString *)bundleIdentifier {
    NSString *bundleId = %orig;
    if ([bundleId isEqualToString:@"com.apple.springboard"]) {
        return bundleId;
    }
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [self setupFridaRuntime];
    });
    
    return bundleId;
}

%new
- (void)setupFridaRuntime {
    NSString *fridaScript = @"Interceptor.attach(ObjC.classes.UIViewController['- viewDidAppear:'].implementation, {onEnter: function(args) {console.log('[Frida] ' + ObjC.Object(args[0]) + ' viewDidAppear:');}});var classes = ObjC.classes;for (var className in classes) {if (ObjC.classes.hasOwnProperty(className)) {console.log('[Frida] Found class: ' + className);}}";
    [self loadFridaScript:fridaScript];
}

%new
- (void)loadFridaScript:(NSString *)script {
    NSError *error;
    NSString *scriptPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"frida_script.js"];
    [script writeToFile:scriptPath atomically:YES encoding:NSUTF8StringEncoding error:&error];
    
    if (!error) {
        pid_t pid;
        const char *args[] = {
            "/usr/local/bin/frida",
            "-U",
            "-l",
            [scriptPath UTF8String],
            "-f",
            [[[NSBundle mainBundle] bundleIdentifier] UTF8String],
            NULL
        };
        
        char *const argv[] = {(char *)args[0], (char *)args[1], (char *)args[2], 
                            (char *)args[3], (char *)args[4], (char *)args[5], NULL};
        
        posix_spawn(&pid, args[0], NULL, NULL, argv, NULL);
        
        int status;
        waitpid(pid, &status, 0);
    }
}

%new
- (void)fridaOutput:(NSNotification *)notification {
    NSData *data = notification.userInfo[NSFileHandleNotificationDataItem];
    if (data.length) {
        NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSLog(@"[Frida Output] %@", output);
        
        NSFileHandle *file = notification.object;
        [file readInBackgroundAndNotify];
    }
}

%end

#if IS_DYLIB_MODE
__attribute__((constructor)) static void entry() {
    NSLog(@"[DynamicProbe] 动态库模式启动");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[DynamicProbeTweak sharedInstance] setup];
    });
}
#endif
