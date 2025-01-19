#import "ProbeMenuViewController.h"
#import <objc/runtime.h>
#import <mach/mach.h>
#import <mach/mach_host.h>
#import <mach/processor_info.h>

@interface UIImageView (DynamicProbe)
- (void)dp_setImage:(UIImage *)image;
@end

@interface UIImage (DynamicProbe)
+ (UIImage *)dp_imageNamed:(NSString *)name;
@end

@interface ProbeMenuViewController () {
    BOOL _isMeasuring;
}
@property (nonatomic, strong) NSMutableArray *classList;
@property (nonatomic, strong) UITextView *outputTextView;
@property (nonatomic, strong) NSMutableDictionary *hookedMethods;
@property (nonatomic, strong) UIView *selectionView;
@property (nonatomic, strong) UIWindow *inspectorWindow;
@property (nonatomic, weak) UIView *selectedView;
@property (nonatomic, strong) UISearchBar *searchBar;
@property (nonatomic, strong) NSMutableArray *filteredItems;
@property (nonatomic, strong, readwrite) NSArray *menuSections;
@property (nonatomic, strong) UIWindow *imageInspectorWindow;
@property (nonatomic, strong) UITableView *imageListTableView;
@property (nonatomic, strong, readwrite) NSMutableArray *fridaScripts;
@property (nonatomic, strong, readwrite) NSMutableDictionary *hookResults;
@end

@implementation ProbeMenuViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0.95 alpha:1.0];
    self.menuSections = @[
        @{
            @"title": @"全局",
            @"items": @[
                @{@"title": @"UI检查器", @"image": @"viewfinder"},
                @{@"title": @"图片捕获", @"image": @"photo"},
                @{@"title": @"网络监控", @"image": @"network"},
                @{@"title": @"系统日志", @"image": @"text.alignleft"}
            ]
        },
        @{
            @"title": @"开发工具",
            @"items": @[
                @{@"title": @"类浏览器", @"image": @"doc.text"},
                @{@"title": @"方法监控", @"image": @"eye"},
                @{@"title": @"生成头文件", @"image": @"doc.plaintext"},
                @{@"title": @"沙盒文件", @"image": @"folder"}
            ]
        },
        @{
            @"title": @"系统信息",
            @"items": @[
                @{@"title": @"设备信息", @"image": @"iphone"},
                @{@"title": @"内存使用", @"image": @"memorychip"},
                @{@"title": @"CPU使用率", @"image": @"gauge"}
            ]
        },
        @{
            @"title": @"Frida 功能",
            @"items": @[
                @{@"title": @"类浏览器", @"image": @"doc.text"},
                @{@"title": @"方法跟踪", @"image": @"arrow.branch"},
                @{@"title": @"内存搜索", @"image": @"magnifyingglass"},
                @{@"title": @"脚本注入", @"image": @"text.badge.plus"}
            ]
        }
    ];
    
    self.searchBar = [[UISearchBar alloc] initWithFrame:CGRectMake(0, 0, self.view.bounds.size.width, 44)];
    self.searchBar.placeholder = @"搜索功能";
    self.searchBar.delegate = self;
    self.searchBar.searchBarStyle = UISearchBarStyleMinimal;
    
    self.menuTableView = [[UITableView alloc] initWithFrame:self.view.bounds style:UITableViewStyleGrouped];
    self.menuTableView.delegate = self;
    self.menuTableView.dataSource = self;
    self.menuTableView.tableHeaderView = self.searchBar;
    self.menuTableView.backgroundColor = [UIColor clearColor];
    self.menuTableView.separatorStyle = UITableViewCellSeparatorStyleSingleLine;
    self.menuTableView.separatorInset = UIEdgeInsetsMake(0, 15, 0, 15);
    [self.view addSubview:self.menuTableView];
    
    [self.menuTableView registerClass:[UITableViewCell class] forCellReuseIdentifier:@"MenuCell"];
    
    self.classList = [NSMutableArray array];
    self.hookedMethods = [NSMutableDictionary dictionary];
    self.fridaScripts = [NSMutableArray array];
    self.hookResults = [NSMutableDictionary dictionary];
    
    self.outputTextView = [[UITextView alloc] initWithFrame:CGRectMake(10, 50, self.view.bounds.size.width - 20, 200)];
    self.outputTextView.backgroundColor = [UIColor colorWithWhite:0.1 alpha:0.8];
    self.outputTextView.textColor = [UIColor whiteColor];
    self.outputTextView.font = [UIFont systemFontOfSize:12];
    self.outputTextView.editable = NO;
    self.outputTextView.hidden = YES;
    [self.view addSubview:self.outputTextView];
}

- (void)closeMenu {
    [[DynamicProbeTweak sharedInstance] hideMenu];
}

#pragma mark - UITableViewDataSource

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    if (tableView == self.menuTableView) {
        return self.menuSections.count;
    }
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (tableView == self.menuTableView) {
        NSDictionary *sectionData = self.menuSections[section];
        NSArray *items = sectionData[@"items"];
        return items.count;
    } else if (tableView == self.imageListTableView) {
        return self.capturedImages.count;
    }
    return 0;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (tableView == self.menuTableView) {
        NSDictionary *sectionData = self.menuSections[section];
        return sectionData[@"title"];
    }
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (tableView == self.menuTableView) {
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"MenuCell"];
        
        NSDictionary *sectionData = self.menuSections[indexPath.section];
        NSArray *items = sectionData[@"items"];
        NSDictionary *item = items[indexPath.row];
        
        cell.textLabel.text = item[@"title"];
        cell.imageView.image = [UIImage systemImageNamed:item[@"image"]];
        cell.imageView.tintColor = [UIColor systemBlueColor];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        
        cell.backgroundColor = [UIColor whiteColor];
        cell.textLabel.font = [UIFont systemFontOfSize:16];
        cell.selectionStyle = UITableViewCellSelectionStyleGray;
        
        return cell;
    } else if (tableView == self.imageListTableView) {
        UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"ImageCell"];
        
        UIImage *image = self.capturedImages[indexPath.row];
        UIImageView *imageView = self.imageViewMap[@(image.hash)];
        
        cell.backgroundColor = [UIColor clearColor];
        cell.imageView.image = image;
        cell.textLabel.textColor = [UIColor whiteColor];
        cell.textLabel.numberOfLines = 0;
        
        NSMutableString *info = [NSMutableString string];
        [info appendFormat:@"大小: %.2f KB\n", image.size.width * image.size.height * 4 / 1024.0];
        [info appendFormat:@"尺寸: %.0f x %.0f\n", image.size.width, image.size.height];
        if (imageView) {
            [info appendFormat:@"所在视图: %@", NSStringFromClass([imageView class])];
        }
        
        cell.textLabel.text = info;
        
        return cell;
    }
    
    return nil;
}

#pragma mark - UITableViewDelegate

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    
    if (tableView == self.menuTableView) {
        NSDictionary *sectionData = self.menuSections[indexPath.section];
        NSArray *items = sectionData[@"items"];
        NSDictionary *item = items[indexPath.row];
        NSString *title = item[@"title"];
        
        if ([title isEqualToString:@"UI检查器"]) {
            [self startUIInspecting];
        } else if ([title isEqualToString:@"类浏览器"]) {
            [self showFridaClassBrowser];
        } else if ([title isEqualToString:@"方法监控"]) {
            [self setupMethodMonitoring];
        } else if ([title isEqualToString:@"生成头文件"]) {
            [self generateHeaders];
        } else if ([title isEqualToString:@"图片捕获"]) {
            [self startImageCapture];
        } else if ([title isEqualToString:@"方法跟踪"]) {
            [self setupMethodTracing];
        } else if ([title isEqualToString:@"内存搜索"]) {
            [self showMemorySearch];
        } else if ([title isEqualToString:@"脚本注入"]) {
            [self showScriptInjection];
        }
    } else if (tableView == self.imageListTableView) {
        UIImage *image = self.capturedImages[indexPath.row];
        UIImageView *imageView = self.imageViewMap[@(image.hash)];
        
        if (imageView) {
            [self highlightView:imageView];
            [self showInspectorForView:imageView];
        }
        
        [self showImageDetails:image];
    }
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    return 50;
}

- (CGFloat)tableView:(UITableView *)tableView heightForHeaderInSection:(NSInteger)section {
    return 30;
}

- (UIView *)tableView:(UITableView *)tableView viewForHeaderInSection:(NSInteger)section {
    UIView *headerView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, tableView.bounds.size.width, 30)];
    headerView.backgroundColor = [UIColor colorWithWhite:0.95 alpha:1.0];
    
    UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(15, 5, tableView.bounds.size.width - 30, 20)];
    titleLabel.text = [self tableView:tableView titleForHeaderInSection:section];
    titleLabel.font = [UIFont boldSystemFontOfSize:13];
    titleLabel.textColor = [UIColor darkGrayColor];
    
    [headerView addSubview:titleLabel];
    return headerView;
}

#pragma mark - 功能实现

- (void)showClassList:(NSArray *)classes {
    self.outputTextView.hidden = NO;
    self.menuTableView.hidden = YES;
    
    NSMutableString *output = [NSMutableString string];
    [output appendString:@"类列表：\n\n"];
    
    for (NSDictionary *classInfo in classes) {
        NSString *className = classInfo[@"name"];
        NSArray *methods = classInfo[@"methods"];
        
        [output appendFormat:@"类名: %@\n", className];
        [output appendString:@"方法列表:\n"];
        for (NSString *method in methods) {
            [output appendFormat:@"  %@\n", method];
        }
        [output appendString:@"\n"];
    }
    
    self.outputTextView.text = output;
    
    // 添加返回按钮
    UIButton *backButton = [UIButton buttonWithType:UIButtonTypeSystem];
    backButton.frame = CGRectMake(10, 10, 60, 30);
    [backButton setTitle:@"返回" forState:UIControlStateNormal];
    [backButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [backButton addTarget:self action:@selector(backToMenu) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:backButton];
}

- (void)setupMethodMonitoring {
    self.outputTextView.hidden = NO;
    self.menuTableView.hidden = YES;
    
    UITextField *classInput = [[UITextField alloc] initWithFrame:CGRectMake(10, 10, self.view.bounds.size.width - 20, 40)];
    classInput.backgroundColor = [UIColor colorWithWhite:0.2 alpha:0.8];
    classInput.textColor = [UIColor whiteColor];
    classInput.placeholder = @"输入要监控的类名";
    [self.view addSubview:classInput];
    
    UIButton *monitorButton = [UIButton buttonWithType:UIButtonTypeSystem];
    monitorButton.frame = CGRectMake(10, 60, 100, 30);
    [monitorButton setTitle:@"开始监控" forState:UIControlStateNormal];
    [monitorButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [monitorButton addTarget:self action:@selector(startMonitoring:) forControlEvents:UIControlEventTouchUpInside];
    monitorButton.tag = classInput.hash;
    [self.view addSubview:monitorButton];
    
    UIButton *backButton = [UIButton buttonWithType:UIButtonTypeSystem];
    backButton.frame = CGRectMake(10, self.view.bounds.size.height - 40, 60, 30);
    [backButton setTitle:@"返回" forState:UIControlStateNormal];
    [backButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [backButton addTarget:self action:@selector(backToMenu) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:backButton];
    
    UISearchBar *searchBar = [[UISearchBar alloc] initWithFrame:CGRectMake(10, 110, self.view.bounds.size.width - 20, 44)];
    searchBar.placeholder = @"搜索类名";
    searchBar.delegate = self;
    searchBar.backgroundColor = [UIColor clearColor];
    [self.view addSubview:searchBar];
}

- (void)startMonitoring:(UIButton *)sender {
    UITextField *classInput = [self.view viewWithTag:sender.tag];
    NSString *className = classInput.text;
    
    if (className.length == 0) {
        self.outputTextView.text = @"请输入有效的类名";
        return;
    }
    
    Class targetClass = NSClassFromString(className);
    if (!targetClass) {
        self.outputTextView.text = @"找不到指定的类";
        return;
    }
    
    NSMutableString *output = [NSMutableString string];
    [output appendFormat:@"监控类: %@\n\n", className];
    
    // 获取所有方法
    unsigned int methodCount;
    Method *methods = class_copyMethodList(targetClass, &methodCount);
    
    for (unsigned int i = 0; i < methodCount; i++) {
        Method method = methods[i];
        SEL selector = method_getName(method);
        NSString *methodName = NSStringFromSelector(selector);
        
        // 添加方法监控
        [self hookMethod:selector ofClass:targetClass];
        [output appendFormat:@"已监控方法: %@\n", methodName];
    }
    
    free(methods);
    self.outputTextView.text = output;
}

- (void)hookMethod:(SEL)selector ofClass:(Class)class {
    // 创建方法监控
    Method method = class_getInstanceMethod(class, selector);
    if (!method) return;
    
    IMP originalImp = method_getImplementation(method);
    
    __weak typeof(self) weakSelf = self;
    IMP newImp = imp_implementationWithBlock(^id(id self, ...){
        // 记录方法调用
        NSString *log = [NSString stringWithFormat:@"调用方法: [%@ %@]", 
                        NSStringFromClass([self class]), 
                        NSStringFromSelector(selector)];
        [weakSelf appendLog:log];
        
        // 获取参数和返回值
        va_list args;
        va_start(args, self);
        NSMutableArray *arguments = [NSMutableArray array];
        for (int i = 2; i < method_getNumberOfArguments(method); i++) {
            char *argType = method_copyArgumentType(method, i);
            if (argType) {
                id arg = va_arg(args, id);
                if (arg) {
                    [arguments addObject:arg];
                }
                free(argType);
            }
        }
        va_end(args);
        
        if (arguments.count > 0) {
            [weakSelf appendLog:[NSString stringWithFormat:@"参数: %@", arguments]];
        }
        
        // 调用原始方法
        id result = ((id (*)(id, SEL, ...))originalImp)(self, selector);
        
        if (result) {
            [weakSelf appendLog:[NSString stringWithFormat:@"返回值: %@", result]];
        }
        
        return result;
    });
    
    method_setImplementation(method, newImp);
    self.hookedMethods[NSStringFromSelector(selector)] = @(YES);
}

- (void)appendLog:(NSString *)log {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.outputTextView.text = [self.outputTextView.text stringByAppendingFormat:@"%@\n", log];
    });
}

- (void)generateHeaders {
    self.outputTextView.hidden = NO;
    self.menuTableView.hidden = YES;
    
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleLarge];
    spinner.center = self.view.center;
    [self.view addSubview:spinner];
    [spinner startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSMutableString *output = [NSMutableString string];
        unsigned int classCount;
        Class *classes = objc_copyClassList(&classCount);
        NSMutableSet *processedClasses = [NSMutableSet set];
        
        for (unsigned int i = 0; i < classCount; i++) {
            Class cls = classes[i];
            NSString *className = NSStringFromClass(cls);
            
            if ([className hasPrefix:@"NS"] || [className hasPrefix:@"UI"] || 
                [processedClasses containsObject:className]) {
                continue;
            }
            
            [processedClasses addObject:className];
            [output appendFormat:@"@interface %@ : %@\n", 
             className, 
             NSStringFromClass(class_getSuperclass(cls))];
            
            unsigned int protocolCount;
            Protocol * __unsafe_unretained *protocols = class_copyProtocolList(cls, &protocolCount);
            if (protocolCount > 0) {
                [output appendString:@" <"];
                for (unsigned int j = 0; j < protocolCount; j++) {
                    Protocol *protocol = protocols[j];
                    [output appendFormat:@"%s%@", 
                     j == 0 ? "" : ", ", 
                     NSStringFromProtocol(protocol)];
                }
                [output appendString:@">"];
            }
            free(protocols);
            
            [output appendString:@"\n\n"];
            
            unsigned int ivarCount;
            Ivar *ivars = class_copyIvarList(cls, &ivarCount);
            if (ivarCount > 0) {
                for (unsigned int j = 0; j < ivarCount; j++) {
                    Ivar ivar = ivars[j];
                    const char *ivarName = ivar_getName(ivar);
                    const char *ivarType = ivar_getTypeEncoding(ivar);
                    [output appendFormat:@"@property (nonatomic) %@ %s; %s\n", 
                     [self decodeType:ivarType], 
                     ivarName,
                     ivarType];
                }
                [output appendString:@"\n"];
            }
            free(ivars);
            
            // 获取属性列表
            unsigned int propertyCount;
            objc_property_t *properties = class_copyPropertyList(cls, &propertyCount);
            if (propertyCount > 0) {
                for (unsigned int j = 0; j < propertyCount; j++) {
                    objc_property_t property = properties[j];
                    [self appendPropertyDescription:property toString:output];
                }
                [output appendString:@"\n"];
            }
            free(properties);
            
            // 获取实例方法列表
            unsigned int methodCount;
            Method *methods = class_copyMethodList(cls, &methodCount);
            if (methodCount > 0) {
                for (unsigned int j = 0; j < methodCount; j++) {
                    Method method = methods[j];
                    [self appendMethodDescription:method toString:output isClassMethod:NO];
                }
                [output appendString:@"\n"];
            }
            free(methods);
            
            // 获取类方法列表
            Method *classMethods = class_copyMethodList(object_getClass(cls), &methodCount);
            if (methodCount > 0) {
                for (unsigned int j = 0; j < methodCount; j++) {
                    Method method = classMethods[j];
                    [self appendMethodDescription:method toString:output isClassMethod:YES];
                }
                [output appendString:@"\n"];
            }
            free(classMethods);
            
            [output appendString:@"@end\n\n"];
            [output appendString:@"--------------------------------\n\n"];
        }
        
        free(classes);
        
        // 保存到文件
        NSString *documentsPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *headerPath = [documentsPath stringByAppendingPathComponent:@"DecryptedHeaders.h"];
        [output writeToFile:headerPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [spinner stopAnimating];
            [spinner removeFromSuperview];
            self.outputTextView.text = [NSString stringWithFormat:@"头文件已生成到:\n%@", headerPath];
            
            // 添加分享按钮
            UIButton *shareButton = [UIButton buttonWithType:UIButtonTypeSystem];
            shareButton.frame = CGRectMake(10, self.view.bounds.size.height - 50, 100, 40);
            [shareButton setTitle:@"分享文件" forState:UIControlStateNormal];
            [shareButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
            [shareButton addTarget:self action:@selector(shareHeaderFile) forControlEvents:UIControlEventTouchUpInside];
            [self.view addSubview:shareButton];
        });
    });
}

#pragma mark - 头文件生成辅助方法

- (void)appendPropertyDescription:(objc_property_t)property toString:(NSMutableString *)output {
    const char *name = property_getName(property);
    const char *attributes = property_getAttributes(property);
    
    // 解析属性特性
    NSString *attributeString = [NSString stringWithUTF8String:attributes];
    NSArray *attributeItems = [attributeString componentsSeparatedByString:@","];
    
    NSMutableArray *propertyAttributes = [NSMutableArray array];
    NSString *propertyType = nil;
    
    for (NSString *attribute in attributeItems) {
        if ([attribute hasPrefix:@"T"]) {
            propertyType = [self decodePropertyType:[attribute substringFromIndex:1]];
        }
        if ([attribute isEqualToString:@"R"]) {
            [propertyAttributes addObject:@"readonly"];
        }
        if ([attribute isEqualToString:@"C"]) {
            [propertyAttributes addObject:@"copy"];
        }
        if ([attribute isEqualToString:@"&"]) {
            [propertyAttributes addObject:@"strong"];
        }
        if ([attribute isEqualToString:@"W"]) {
            [propertyAttributes addObject:@"weak"];
        }
        if ([attribute isEqualToString:@"N"]) {
            [propertyAttributes addObject:@"nonatomic"];
        }
    }
    
    [output appendFormat:@"@property (%@) %@ %s;\n",
     [propertyAttributes componentsJoinedByString:@", "],
     propertyType ?: @"id",
     name];
}

- (void)appendMethodDescription:(Method)method toString:(NSMutableString *)output isClassMethod:(BOOL)isClassMethod {
    SEL selector = method_getName(method);
    NSString *selectorName = NSStringFromSelector(selector);
    
    // 获取参数和返回值类型
    char *returnType = method_copyReturnType(method);
    NSString *returnTypeString = [self decodeType:returnType];
    free(returnType);
    
    NSMutableArray *parameters = [NSMutableArray array];
    unsigned int argumentCount = method_getNumberOfArguments(method);
    
    // 跳过 self 和 _cmd 参数
    for (unsigned int k = 2; k < argumentCount; k++) {
        char *argumentType = method_copyArgumentType(method, k);
        NSString *parameterType = [self decodeType:argumentType];
        [parameters addObject:parameterType];
        free(argumentType);
    }
    
    // 构建方法声明
    [output appendFormat:@"%@ (%@)%@%@;\n",
     isClassMethod ? @"+" : @"-",
     returnTypeString,
     selectorName,
     parameters.count > 0 ? [NSString stringWithFormat:@" (%@)arg", [parameters componentsJoinedByString:@", "]] : @""];
}

- (NSString *)decodeType:(const char *)encodedType {
    if (!encodedType) return @"id";
    
    // 基本类型映射
    NSDictionary *typeMapping = @{
        @"c": @"char",
        @"i": @"int",
        @"s": @"short",
        @"l": @"long",
        @"q": @"long long",
        @"C": @"unsigned char",
        @"I": @"unsigned int",
        @"S": @"unsigned short",
        @"L": @"unsigned long",
        @"Q": @"unsigned long long",
        @"f": @"float",
        @"d": @"double",
        @"B": @"BOOL",
        @"v": @"void",
        @"*": @"char *",
        @"@": @"id",
        @"#": @"Class",
        @":": @"SEL",
    };
    
    NSString *type = [NSString stringWithUTF8String:encodedType];
    
    // 处理对象类型
    if ([type hasPrefix:@"@\""]) {
        NSString *className = [type substringWithRange:NSMakeRange(2, type.length - 3)];
        return className;
    }
    
    // 处理基本类型
    NSString *decodedType = typeMapping[type];
    if (decodedType) {
        return decodedType;
    }
    
    return @"id";
}

- (NSString *)decodePropertyType:(NSString *)encodedType {
    if ([encodedType hasPrefix:@"@\""]) {
        // 对象类型
        NSString *className = [encodedType substringWithRange:NSMakeRange(2, encodedType.length - 3)];
        return className;
    } else if ([encodedType isEqualToString:@"@"]) {
        return @"id";
    } else {
        // 使用类型解码方法
        return [self decodeType:[encodedType UTF8String]];
    }
}

- (void)shareHeaderFile {
    NSString *documentsPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *headerPath = [documentsPath stringByAppendingPathComponent:@"DecryptedHeaders.h"];
    
    NSURL *fileURL = [NSURL fileURLWithPath:headerPath];
    UIActivityViewController *activityVC = [[UIActivityViewController alloc] initWithActivityItems:@[fileURL]
                                                                           applicationActivities:nil];
    
    if ([UIDevice currentDevice].userInterfaceIdiom == UIUserInterfaceIdiomPad) {
        activityVC.popoverPresentationController.sourceView = self.view;
        activityVC.popoverPresentationController.sourceRect = CGRectMake(self.view.bounds.size.width/2, 
                                                                        self.view.bounds.size.height/2, 
                                                                        0, 0);
    }
    
    [self presentViewController:activityVC animated:YES completion:nil];
}

- (void)backToMenu {
    self.outputTextView.hidden = YES;
    self.menuTableView.hidden = NO;
    
    // 移除所有临时添加的视图
    for (UIView *view in self.view.subviews) {
        if (view != self.menuTableView && view != self.outputTextView) {
            [view removeFromSuperview];
        }
    }
}

// 添加搜索功能支持
- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)searchText {
    if (searchText.length == 0) {
        self.outputTextView.text = @"请输入要搜索的类名";
        return;
    }
    
    NSMutableString *output = [NSMutableString string];
    [output appendString:@"搜索结果：\n\n"];
    
    for (NSString *className in self.classList) {
        if ([className.lowercaseString containsString:searchText.lowercaseString]) {
            [output appendFormat:@"%@\n", className];
        }
    }
    
    self.outputTextView.text = output;
}

#pragma mark - UI Inspection

- (void)startUIInspecting {
    self.isInspecting = YES;
    [[DynamicProbeTweak sharedInstance] hideMenu];
    
    // 创建选择指示器
    if (!self.selectionView) {
        self.selectionView = [[UIView alloc] init];
        self.selectionView.layer.borderColor = [UIColor redColor].CGColor;
        self.selectionView.layer.borderWidth = 2.0;
        self.selectionView.backgroundColor = [UIColor colorWithRed:1 green:0 blue:0 alpha:0.2];
    }
    
    // 创建检查窗口
    if (!self.inspectorWindow) {
        self.inspectorWindow = [[UIWindow alloc] initWithFrame:CGRectMake(0, 0, UIScreen.mainScreen.bounds.size.width, 200)];
        self.inspectorWindow.windowLevel = UIWindowLevelStatusBar;
        self.inspectorWindow.backgroundColor = [UIColor colorWithWhite:0 alpha:0.8];
        self.inspectorWindow.hidden = YES;
        self.inspectorWindow.layer.cornerRadius = 10;
        self.inspectorWindow.clipsToBounds = YES;
    }
    
    // 添加手势识别器
    UITapGestureRecognizer *tapGesture = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(handleTap:)];
    UIPanGestureRecognizer *panGesture = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
    
    // 将手势添加到主窗口
    UIWindow *mainWindow = [[UIApplication sharedApplication].windows firstObject];
    [mainWindow addGestureRecognizer:tapGesture];
    [mainWindow addGestureRecognizer:panGesture];
}

- (void)handleTap:(UITapGestureRecognizer *)gesture {
    CGPoint location = [gesture locationInView:gesture.view];
    [self selectViewAtPoint:location];
}

- (void)handlePan:(UIPanGestureRecognizer *)gesture {
    CGPoint location = [gesture locationInView:gesture.view];
    [self selectViewAtPoint:location];
}

- (void)selectViewAtPoint:(CGPoint)point {
    UIWindow *window = [[UIApplication sharedApplication].windows firstObject];
    UIView *view = [self hitTest:point inView:window];
    
    if (view && view != window) {
        [self highlightView:view];
        [self showInspectorForView:view];
    }
}

- (UIView *)hitTest:(CGPoint)point inView:(UIView *)view {
    if (!view.isUserInteractionEnabled || view.isHidden || view.alpha < 0.01) {
        return nil;
    }
    
    for (UIView *subview in view.subviews.reverseObjectEnumerator) {
        CGPoint convertedPoint = [view convertPoint:point toView:subview];
        UIView *hitView = [self hitTest:convertedPoint inView:subview];
        if (hitView) {
            return hitView;
        }
    }
    
    if ([view pointInside:point withEvent:nil]) {
        return view;
    }
    
    return nil;
}

- (void)highlightView:(UIView *)view {
    self.selectedView = view;
    
    // 更新选择指示器的位置和大小
    CGRect frame = [view convertRect:view.bounds toView:nil];
    self.selectionView.frame = frame;
    
    if (self.selectionView.superview != [[UIApplication sharedApplication].windows firstObject]) {
        [[[UIApplication sharedApplication].windows firstObject] addSubview:self.selectionView];
    }
}

- (void)showInspectorForView:(UIView *)view {
    // 显示检查窗口
    self.inspectorWindow.hidden = NO;
    
    // 创建视图信息
    NSMutableString *info = [NSMutableString string];
    [info appendFormat:@"类名: %@\n", NSStringFromClass([view class])];
    [info appendFormat:@"Frame: %@\n", NSStringFromCGRect(view.frame)];
    [info appendFormat:@"Tag: %ld\n", (long)view.tag];
    
    if ([view isKindOfClass:[UILabel class]]) {
        UILabel *label = (UILabel *)view;
        [info appendFormat:@"Text: %@\n", label.text];
    } else if ([view isKindOfClass:[UIButton class]]) {
        UIButton *button = (UIButton *)view;
        [info appendFormat:@"Title: %@\n", [button titleForState:UIControlStateNormal]];
    }
    
    // 创建或更新信息标签
    UILabel *infoLabel = [self.inspectorWindow viewWithTag:1001];
    if (!infoLabel) {
        infoLabel = [[UILabel alloc] initWithFrame:self.inspectorWindow.bounds];
        infoLabel.tag = 1001;
        infoLabel.numberOfLines = 0;
        infoLabel.textColor = [UIColor whiteColor];
        infoLabel.font = [UIFont systemFontOfSize:12];
        [self.inspectorWindow addSubview:infoLabel];
    }
    infoLabel.text = info;
    
    // 添加视图层级按钮
    UIButton *hierarchyButton = [self.inspectorWindow viewWithTag:1002];
    if (!hierarchyButton) {
        hierarchyButton = [UIButton buttonWithType:UIButtonTypeSystem];
        hierarchyButton.tag = 1002;
        hierarchyButton.frame = CGRectMake(10, 160, 100, 30);
        [hierarchyButton setTitle:@"查看层级" forState:UIControlStateNormal];
        [hierarchyButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [hierarchyButton addTarget:self action:@selector(showViewHierarchy) forControlEvents:UIControlEventTouchUpInside];
        [self.inspectorWindow addSubview:hierarchyButton];
    }
}

- (void)showViewHierarchy {
    if (!self.selectedView) return;
    
    NSMutableString *hierarchy = [NSMutableString string];
    UIView *view = self.selectedView;
    int level = 0;
    
    while (view) {
        [hierarchy insertString:[NSString stringWithFormat:@"%@%@\n", 
                               [@"" stringByPaddingToLength:level withString:@"  " startingAtIndex:0],
                               NSStringFromClass([view class])] 
                      atIndex:0];
        view = view.superview;
        level++;
    }
    
    // 显示层级信息
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"视图层级"
                                                                  message:hierarchy
                                                           preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
    [[[UIApplication sharedApplication].windows firstObject].rootViewController presentViewController:alert animated:YES completion:nil];
}

- (void)stopUIInspecting {
    self.isInspecting = NO;
    [self.selectionView removeFromSuperview];
    self.inspectorWindow.hidden = YES;
    
    // 移除手势识别器
    UIWindow *mainWindow = [[UIApplication sharedApplication].windows firstObject];
    for (UIGestureRecognizer *gesture in mainWindow.gestureRecognizers) {
        [mainWindow removeGestureRecognizer:gesture];
    }
}

#pragma mark - 系统监控功能

- (void)showSystemInfo {
    NSMutableString *info = [NSMutableString string];
    
    // 设备信息
    UIDevice *device = [UIDevice currentDevice];
    [info appendFormat:@"设备名称: %@\n", device.name];
    [info appendFormat:@"系统版本: %@ %@\n", device.systemName, device.systemVersion];
    [info appendFormat:@"设备型号: %@\n", device.model];
    
    // 内存信息
    mach_port_t host_port;
    mach_msg_type_number_t host_size;
    vm_size_t pagesize;
    vm_statistics_data_t vm_stat;

    host_port = mach_host_self();
    host_size = sizeof(vm_statistics_data_t) / sizeof(integer_t);

    if (host_page_size(host_port, &pagesize) == KERN_SUCCESS &&
        host_statistics(host_port, HOST_VM_INFO, (host_info_t)&vm_stat, &host_size) == KERN_SUCCESS) {
        
        natural_t mem_free = vm_stat.free_count * pagesize;
        natural_t mem_used = (vm_stat.active_count + vm_stat.inactive_count + vm_stat.wire_count) * pagesize;
        
        [info appendFormat:@"\n内存使用:\n"];
        [info appendFormat:@"已用: %.2f MB\n", mem_used / 1024.0 / 1024.0];
        [info appendFormat:@"可用: %.2f MB\n", mem_free / 1024.0 / 1024.0];
    }
    
    // CPU信息
    processor_info_array_t cpuInfo;
    mach_msg_type_number_t numCpuInfo;
    natural_t numCPUs = 0;
    
    if (host_processor_info(mach_host_self(), PROCESSOR_CPU_LOAD_INFO, &numCPUs, &cpuInfo, &numCpuInfo) == KERN_SUCCESS) {
        [info appendFormat:@"\nCPU使用率:\n"];
        for (unsigned i = 0; i < numCPUs; i++) {
            float inUse = cpuInfo[(CPU_STATE_MAX * i) + CPU_STATE_USER] + 
                         cpuInfo[(CPU_STATE_MAX * i) + CPU_STATE_SYSTEM];
            float total = inUse + cpuInfo[(CPU_STATE_MAX * i) + CPU_STATE_IDLE];
            [info appendFormat:@"CPU %u: %.1f%%\n", i, (inUse / total) * 100.0];
        }
        vm_deallocate(mach_task_self(), (vm_address_t)cpuInfo, sizeof(integer_t) * numCpuInfo);
    }
    
    [self showInfoWithTitle:@"系统信息" message:info];
}

#pragma mark - 网络监控功能

- (void)setupNetworkMonitoring {
    // 创建网络监控视图
    UIView *monitorView = [[UIView alloc] initWithFrame:self.view.bounds];
    monitorView.backgroundColor = [UIColor colorWithWhite:0.1 alpha:0.9];
    [self.view addSubview:monitorView];
    
    // 添加请求列表
    UITableView *requestTable = [[UITableView alloc] initWithFrame:CGRectMake(0, 44, self.view.bounds.size.width, self.view.bounds.size.height - 44)
                                                           style:UITableViewStylePlain];
    requestTable.backgroundColor = [UIColor clearColor];
    requestTable.delegate = self;
    requestTable.dataSource = self;
    [monitorView addSubview:requestTable];
    
    // 添加工具栏
    UIToolbar *toolbar = [[UIToolbar alloc] initWithFrame:CGRectMake(0, 0, self.view.bounds.size.width, 44)];
    toolbar.barStyle = UIBarStyleBlack;
    toolbar.translucent = YES;
    
    UIBarButtonItem *clearButton = [[UIBarButtonItem alloc] initWithTitle:@"清除"
                                                                   style:UIBarButtonItemStylePlain
                                                                  target:self
                                                                  action:@selector(clearNetworkLogs)];
    
    UIBarButtonItem *closeButton = [[UIBarButtonItem alloc] initWithTitle:@"关闭"
                                                                   style:UIBarButtonItemStyleDone
                                                                  target:self
                                                                  action:@selector(closeNetworkMonitor)];
    
    toolbar.items = @[clearButton, closeButton];
    [monitorView addSubview:toolbar];
}

#pragma mark - 沙盒文件浏览器

- (void)showSandboxBrowser {
    NSString *documentsPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    [self showDirectoryContents:documentsPath];
}

- (void)showDirectoryContents:(NSString *)path {
    NSError *error;
    NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:path error:&error];
    
    if (error) {
        [self showInfoWithTitle:@"错误" message:error.localizedDescription];
        return;
    }
    
    UITableView *fileList = [[UITableView alloc] initWithFrame:self.view.bounds style:UITableViewStylePlain];
    fileList.backgroundColor = [UIColor whiteColor];
    fileList.delegate = self;
    fileList.dataSource = self;
    
    // 存储文件列表数据
    objc_setAssociatedObject(fileList, @"fileContents", contents, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    objc_setAssociatedObject(fileList, @"currentPath", path, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    
    [self.view addSubview:fileList];
}

#pragma mark - 辅助功能

- (void)showInfoWithTitle:(NSString *)title message:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                 message:message
                                                          preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

#pragma mark - UI检查器增强功能

- (void)enhanceUIInspector {
    // 添加测量工具
    UIButton *measureButton = [UIButton buttonWithType:UIButtonTypeSystem];
    measureButton.frame = CGRectMake(self.inspectorWindow.bounds.size.width - 110, 160, 100, 30);
    [measureButton setTitle:@"测量" forState:UIControlStateNormal];
    [measureButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [measureButton addTarget:self action:@selector(toggleMeasurementMode) forControlEvents:UIControlEventTouchUpInside];
    [self.inspectorWindow addSubview:measureButton];
}

- (void)toggleMeasurementMode {
    // 实现视图测量功能
    self.isMeasuring = !self.isMeasuring;
    
    if (self.isMeasuring) {
        // 显示测量指引
        CAShapeLayer *guideLayer = [CAShapeLayer layer];
        guideLayer.strokeColor = [UIColor greenColor].CGColor;
        guideLayer.fillColor = [UIColor clearColor].CGColor;
        guideLayer.lineWidth = 1.0;
        [self.selectionView.layer addSublayer:guideLayer];
        
        // 添加测量标注
        UILabel *measureLabel = [[UILabel alloc] init];
        measureLabel.textColor = [UIColor greenColor];
        measureLabel.font = [UIFont systemFontOfSize:10];
        [self.selectionView addSubview:measureLabel];
    } else {
        // 清除测量相关视图
        [self.selectionView.layer.sublayers makeObjectsPerformSelector:@selector(removeFromSuperlayer)];
        [[self.selectionView subviews] makeObjectsPerformSelector:@selector(removeFromSuperview)];
    }
}

#pragma mark - 手势识别器代理

- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer shouldReceiveTouch:(UITouch *)touch {
    // 防止手势影响UI操作
    if ([touch.view isKindOfClass:[UIControl class]]) {
        return NO;
    }
    return YES;
}

#pragma mark - 图片捕获功能

- (void)startImageCapture {
    if (!self.capturedImages) {
        self.capturedImages = [NSMutableArray array];
    }
    if (!self.imageViewMap) {
        self.imageViewMap = [NSMutableDictionary dictionary];
    }
    
    // 创建图片检查器窗口
    if (!self.imageInspectorWindow) {
        self.imageInspectorWindow = [[UIWindow alloc] initWithFrame:CGRectMake(0, 100, UIScreen.mainScreen.bounds.size.width, 400)];
        self.imageInspectorWindow.windowLevel = UIWindowLevelStatusBar;
        self.imageInspectorWindow.backgroundColor = [UIColor colorWithWhite:0 alpha:0.9];
        self.imageInspectorWindow.layer.cornerRadius = 10;
        self.imageInspectorWindow.clipsToBounds = YES;
        
        // 添加图片列表
        self.imageListTableView = [[UITableView alloc] initWithFrame:self.imageInspectorWindow.bounds style:UITableViewStylePlain];
        self.imageListTableView.backgroundColor = [UIColor clearColor];
        self.imageListTableView.delegate = self;
        self.imageListTableView.dataSource = self;
        self.imageListTableView.rowHeight = 100;
        [self.imageListTableView registerClass:[UITableViewCell class] forCellReuseIdentifier:@"ImageCell"];
        [self.imageInspectorWindow addSubview:self.imageListTableView];
        
        // 添加关闭按钮
        UIButton *closeButton = [UIButton buttonWithType:UIButtonTypeSystem];
        closeButton.frame = CGRectMake(self.imageInspectorWindow.bounds.size.width - 50, 10, 40, 30);
        [closeButton setTitle:@"关闭" forState:UIControlStateNormal];
        [closeButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [closeButton addTarget:self action:@selector(stopImageCapture) forControlEvents:UIControlEventTouchUpInside];
        [self.imageInspectorWindow addSubview:closeButton];
    }
    
    self.imageInspectorWindow.hidden = NO;
    [self startImageMonitoring];
}

- (void)startImageMonitoring {
    // Hook UIImageView的图片设置方法
    [self swizzleImageViewMethods];
    
    // Hook UIImage的创建方法
    [self swizzleImageMethods];
}

- (void)swizzleImageViewMethods {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class class = [UIImageView class];
        
        // Hook setImage:
        SEL originalSelector = @selector(setImage:);
        SEL swizzledSelector = @selector(dp_setImage:);
        
        Method originalMethod = class_getInstanceMethod(class, originalSelector);
        Method swizzledMethod = class_getInstanceMethod(class, swizzledSelector);
        
        method_exchangeImplementations(originalMethod, swizzledMethod);
    });
}

- (void)swizzleImageMethods {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class class = [UIImage class];
        
        // Hook imageNamed:
        SEL originalSelector = @selector(imageNamed:);
        SEL swizzledSelector = @selector(dp_imageNamed:);
        
        Method originalMethod = class_getClassMethod(class, originalSelector);
        Method swizzledMethod = class_getClassMethod(class, swizzledSelector);
        
        method_exchangeImplementations(originalMethod, swizzledMethod);
    });
}

- (void)captureImage:(UIImage *)image fromView:(UIImageView *)imageView {
    if (![self.capturedImages containsObject:image]) {
        [self.capturedImages addObject:image];
        self.imageViewMap[@(image.hash)] = imageView;
        [self.imageListTableView reloadData];
    }
}

- (void)captureImage:(UIImage *)image withName:(NSString *)name {
    if (![self.capturedImages containsObject:image]) {
        [self.capturedImages addObject:image];
        [self.imageListTableView reloadData];
    }
}

- (void)stopImageCapture {
    self.imageInspectorWindow.hidden = YES;
}

#pragma mark - UITableViewDelegate (Image List)

- (void)showImageDetails:(UIImage *)image {
    NSMutableString *details = [NSMutableString string];
    [details appendFormat:@"图片信息:\n\n"];
    [details appendFormat:@"尺寸: %.0f x %.0f\n", image.size.width, image.size.height];
    [details appendFormat:@"比例: %.2f\n", image.scale];
    [details appendFormat:@"方向: %ld\n", (long)image.imageOrientation];
    [details appendFormat:@"大小: %.2f KB\n", image.size.width * image.size.height * 4 / 1024.0];
    
    UIImageView *imageView = self.imageViewMap[@(image.hash)];
    if (imageView) {
        [details appendFormat:@"\n视图信息:\n"];
        [details appendFormat:@"类名: %@\n", NSStringFromClass([imageView class])];
        [details appendFormat:@"Frame: %@\n", NSStringFromCGRect(imageView.frame)];
        [details appendFormat:@"ContentMode: %ld\n", (long)imageView.contentMode];
    }
    
    [self showInfoWithTitle:@"图片详情" message:details];
}

#pragma mark - Frida功能

- (void)showFridaClassBrowser {
    NSString *script = @"\
    var classes = ObjC.classes;\
    var results = [];\
    for (var className in classes) {\
        if (ObjC.classes.hasOwnProperty(className)) {\
            var methods = [];\
            var clazz = classes[className];\
            clazz.$ownMethods.forEach(function(method) {\
                methods.push(method);\
            });\
            results.push({name: className, methods: methods});\
        }\
    }\
    send(JSON.stringify(results));";
    
    [self loadFridaScript:script withCallback:^(NSString *result) {
        NSData *jsonData = [result dataUsingEncoding:NSUTF8StringEncoding];
        NSArray *classes = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:nil];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self showClassList:classes];
        });
    }];
}

- (void)setupMethodTracing {
    NSString *script = @"\
    Interceptor.attach(ObjC.classes.NSObject['- init'].implementation, {\
        onEnter: function(args) {\
            console.log('[Frida] ' + ObjC.Object(args[0]) + ' init');\
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)\
                .map(DebugSymbol.fromAddress).join('\\n'));\
        }\
    });";
    
    [self loadFridaScript:script withCallback:^(NSString *result) {
        NSLog(@"[Frida] Method tracing enabled: %@", result);
    }];
}

- (void)showMemorySearch {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"内存搜索"
                                                                 message:@"输入要搜索的值"
                                                          preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"搜索值";
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"搜索" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *searchValue = alert.textFields.firstObject.text;
        [self performMemorySearch:searchValue];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)performMemorySearch:(NSString *)value {
    NSString *script = [NSString stringWithFormat:@"\
    var pattern = '%@';\
    var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});\
    var results = [];\
    ranges.forEach(function(range) {\
        Memory.scan(range.base, range.size, pattern, {\
            onMatch: function(address, size) {\
                results.push(address.toString());\
            }\
        });\
    });\
    send(JSON.stringify(results));", value];
    
    [self loadFridaScript:script withCallback:^(NSString *result) {
        NSArray *addresses = [NSJSONSerialization JSONObjectWithData:[result dataUsingEncoding:NSUTF8StringEncoding]
                                                           options:0
                                                             error:nil];
        NSLog(@"[Frida] Memory search results: %@", addresses);
    }];
}

- (void)showScriptInjection {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"脚本注入"
                                                                 message:@"输入 Frida 脚本"
                                                          preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"JavaScript 代码";
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"注入" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *script = alert.textFields.firstObject.text;
        [self loadFridaScript:script withCallback:^(NSString *result) {
            NSLog(@"[Frida] Script injection result: %@", result);
        }];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)loadFridaScript:(NSString *)script withCallback:(void (^)(NSString *))callback {
    // 实际项目中需要实现与 Frida 的通信逻辑
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // 这里应该实现实际的 Frida 脚本加载逻辑
        NSString *result = @"Script loaded";
        if (callback) {
            callback(result);
        }
    });
}

@end

// 在 ProbeMenuViewController 实现之后添加类别实现
@implementation UIImageView (DynamicProbe)
- (void)dp_setImage:(UIImage *)image {
    [self dp_setImage:image];
    if (image) {
        ProbeMenuViewController *probe = [DynamicProbeTweak sharedInstance].menuVC;
        [probe captureImage:image fromView:self];
    }
}
@end

@implementation UIImage (DynamicProbe)
+ (UIImage *)dp_imageNamed:(NSString *)name {
    UIImage *image = [self dp_imageNamed:name];
    if (image) {
        ProbeMenuViewController *probe = [DynamicProbeTweak sharedInstance].menuVC;
        [probe captureImage:image withName:name];
    }
    return image;
}
@end 