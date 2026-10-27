-- ---------------------------------------------------------------------------
-- RuoYi 4.7.8 · seed data
--
-- Accounts (real upstream hashes; 4.7.8 uses Shiro Md5Hash(loginName+password+salt),
-- NOT BCrypt -- BCrypt belongs to RuoYi-Vue):
--   admin / admin123   salt=111111  md5("admin"+"admin123"+"111111")
--   ry    / admin123   salt=222222  md5("ry"+"admin123"+"222222")
--
-- Captcha is enabled upstream (shiro.captchaEnabled=true), so interactive login
-- needs the arithmetic captcha from /captcha/captchaImage.
-- ---------------------------------------------------------------------------

SET NAMES utf8mb4;
USE `ry`;

-- ---------------------------------------------------------------------------
-- Departments (deep enough to exercise data-scope SQL)
-- ---------------------------------------------------------------------------
INSERT INTO sys_dept
  (dept_id, parent_id, ancestors, dept_name, order_num, leader, phone, email, status, del_flag, create_by, create_time, update_by, update_time)
VALUES
  (100, 0,   '0',         '若依科技',   0, '若依', '15888888888', 'ry@qq.com', '0', '0', 'admin', NOW(), '', NULL),
  (101, 100, '0,100',     '深圳总公司', 1, '若依', '15888888888', 'ry@qq.com', '0', '0', 'admin', NOW(), '', NULL),
  (102, 100, '0,100',     '长沙分公司', 2, '若依', '15888888888', 'ry@qq.com', '0', '0', 'admin', NOW(), '', NULL),
  (103, 101, '0,100,101', '研发部门',   1, '若依', '15888888888', 'ry@qq.com', '0', '0', 'admin', NOW(), '', NULL),
  (105, 101, '0,100,101', '测试部门',   3, '若依', '15888888888', 'ry@qq.com', '0', '0', 'admin', NOW(), '', NULL);

-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------
INSERT INTO sys_user
  (user_id, dept_id, login_name, user_name, user_type, email, phonenumber, sex, avatar, password, salt, status, del_flag, login_ip, login_date, pwd_update_date, create_by, create_time, update_by, update_time, remark)
VALUES
  (1, 103, 'admin', '若依', '00', 'ry@163.com', '15888888888', '1', '', '29c67a30398638269fe600f73a054934', '111111', '0', '0', '127.0.0.1', NOW(), NOW(), 'admin', NOW(), '', NULL, '管理员'),
  (2, 105, 'ry',    '若依', '00', 'ry@qq.com',  '15666666666', '1', '', '8e6d98b90472783cc73c17047ddccf36', '222222', '0', '0', '127.0.0.1', NOW(), NOW(), 'admin', NOW(), '', NULL, '测试员');

-- ---------------------------------------------------------------------------
-- Roles / user-role / posts
-- ---------------------------------------------------------------------------
INSERT INTO sys_role
  (role_id, role_name, role_key, role_sort, data_scope, status, del_flag, create_by, create_time, update_by, update_time, remark)
VALUES
  (1, '超级管理员', 'admin',  1, '1', '0', '0', 'admin', NOW(), '', NULL, '超级管理员'),
  (2, '普通角色',   'common', 2, '2', '0', '0', 'admin', NOW(), '', NULL, '普通角色');

INSERT INTO sys_user_role (user_id, role_id) VALUES (1, 1), (2, 2);

INSERT INTO sys_post
  (post_id, post_code, post_name, post_sort, status, create_by, create_time, update_by, update_time, remark)
VALUES
  (1, 'ceo', '董事长',   1, '0', 'admin', NOW(), '', NULL, ''),
  (2, 'se',  '项目经理', 2, '0', 'admin', NOW(), '', NULL, '');

INSERT INTO sys_user_post (user_id, post_id) VALUES (1, 1);

-- ---------------------------------------------------------------------------
-- Menus: directories, the pages exercised by ruoyi-scan, and the permission
-- strings behind them. Admin bypasses @RequiresPermissions (isAdmin() adds
-- '*:*:*'), but the rows keep the UI and role-2 grants realistic.
-- ---------------------------------------------------------------------------
INSERT INTO sys_menu
  (menu_id, menu_name, parent_id, order_num, url, target, menu_type, visible, is_refresh, perms, icon, create_by, create_time, update_by, update_time, remark)
VALUES
  (1,   '系统管理',   0,   1, '#',                    '', 'M', '0', '1', '',                        'fa fa-gear',            'admin', NOW(), '', NULL, '系统管理目录'),
  (2,   '系统监控',   0,   2, '#',                    '', 'M', '0', '1', '',                        'fa fa-video-camera',    'admin', NOW(), '', NULL, '系统监控目录'),
  (3,   '系统工具',   0,   3, '#',                    '', 'M', '0', '1', '',                        'fa fa-bars',            'admin', NOW(), '', NULL, '系统工具目录'),
  (100, '用户管理',   1,   1, '/system/user',         '', 'C', '0', '1', 'system:user:view',        'fa fa-user-o',          'admin', NOW(), '', NULL, '用户管理菜单'),
  (101, '角色管理',   1,   2, '/system/role',         '', 'C', '0', '1', 'system:role:view',        'fa fa-user-secret',     'admin', NOW(), '', NULL, '角色管理菜单'),
  (102, '菜单管理',   1,   3, '/system/menu',         '', 'C', '0', '1', 'system:menu:view',        'fa fa-th-list',         'admin', NOW(), '', NULL, '菜单管理菜单'),
  (103, '部门管理',   1,   4, '/system/dept',         '', 'C', '0', '1', 'system:dept:view',        'fa fa-outdent',         'admin', NOW(), '', NULL, '部门管理菜单'),
  (105, '字典管理',   1,   6, '/system/dict',         '', 'C', '0', '1', 'system:dict:view',        'fa fa-bookmark-o',      'admin', NOW(), '', NULL, '字典管理菜单'),
  (106, '参数设置',   1,   7, '/system/config',       '', 'C', '0', '1', 'system:config:view',      'fa fa-sun-o',           'admin', NOW(), '', NULL, '参数设置菜单'),
  (108, '日志管理',   1,   9, '#',                    '', 'M', '0', '1', '',                        'fa fa-pencil-square-o', 'admin', NOW(), '', NULL, '日志管理菜单'),
  (109, '在线用户',   2,   1, '/monitor/online',      '', 'C', '0', '1', 'monitor:online:view',     'fa fa-user-circle',     'admin', NOW(), '', NULL, '在线用户菜单'),
  (110, '定时任务',   2,   2, '/monitor/job',         '', 'C', '0', '1', 'monitor:job:view',        'fa fa-tasks',           'admin', NOW(), '', NULL, '定时任务菜单'),
  (111, '数据监控',   2,   3, '/monitor/data',        '', 'C', '0', '1', 'monitor:data:view',       'fa fa-bug',             'admin', NOW(), '', NULL, '数据监控菜单'),
  (112, '服务监控',   2,   4, '/monitor/server',      '', 'C', '0', '1', 'monitor:server:view',     'fa fa-server',          'admin', NOW(), '', NULL, '服务监控菜单'),
  (113, '缓存监控',   2,   5, '/monitor/cache',       '', 'C', '0', '1', 'monitor:cache:view',      'fa fa-cube',            'admin', NOW(), '', NULL, '缓存监控菜单'),
  (115, '代码生成',   3,   2, '/tool/gen',            '', 'C', '0', '1', 'tool:gen:view',           'fa fa-code',            'admin', NOW(), '', NULL, '代码生成菜单'),
  (500, '操作日志',   108, 1, '/monitor/operlog',     '', 'C', '0', '1', 'monitor:operlog:view',    'fa fa-address-book',    'admin', NOW(), '', NULL, '操作日志菜单'),
  (501, '登录日志',   108, 2, '/monitor/logininfor',  '', 'C', '0', '1', 'monitor:logininfor:view', 'fa fa-file-image-o',    'admin', NOW(), '', NULL, '登录日志菜单'),
  (1000, '用户查询', 100, 1, '#', '', 'F', '0', '1', 'system:user:list',          '#', 'admin', NOW(), '', NULL, ''),
  (1007, '角色查询', 101, 1, '#', '', 'F', '0', '1', 'system:role:list',          '#', 'admin', NOW(), '', NULL, ''),
  (1016, '部门查询', 103, 1, '#', '', 'F', '0', '1', 'system:dept:list',          '#', 'admin', NOW(), '', NULL, ''),
  (1025, '字典查询', 105, 1, '#', '', 'F', '0', '1', 'system:dict:list',          '#', 'admin', NOW(), '', NULL, ''),
  (1030, '参数查询', 106, 1, '#', '', 'F', '0', '1', 'system:config:list',        '#', 'admin', NOW(), '', NULL, ''),
  (1039, '操作查询', 500, 1, '#', '', 'F', '0', '1', 'monitor:operlog:list',      '#', 'admin', NOW(), '', NULL, ''),
  (1043, '登录查询', 501, 1, '#', '', 'F', '0', '1', 'monitor:logininfor:list',   '#', 'admin', NOW(), '', NULL, ''),
  (1047, '在线查询', 109, 1, '#', '', 'F', '0', '1', 'monitor:online:list',       '#', 'admin', NOW(), '', NULL, ''),
  (1050, '任务查询', 110, 1, '#', '', 'F', '0', '1', 'monitor:job:list',          '#', 'admin', NOW(), '', NULL, ''),
  (1052, '任务修改', 110, 3, '#', '', 'F', '0', '1', 'monitor:job:edit',          '#', 'admin', NOW(), '', NULL, ''),
  (1056, '生成查询', 115, 1, '#', '', 'F', '0', '1', 'tool:gen:list',             '#', 'admin', NOW(), '', NULL, ''),
  (1058, '生成修改', 115, 2, '#', '', 'F', '0', '1', 'tool:gen:edit',             '#', 'admin', NOW(), '', NULL, '');

-- Give the non-admin role the seeded menus so account ry is usable after login.
INSERT INTO sys_role_menu (role_id, menu_id)
SELECT 2, menu_id FROM sys_menu;

-- ---------------------------------------------------------------------------
-- Dictionary data (loaded at boot by SysDictTypeServiceImpl.@PostConstruct;
-- copied from the upstream 4.7.8 seed so the UI renders labels correctly)
-- ---------------------------------------------------------------------------

INSERT INTO sys_dict_type VALUES
(1,  '用户性别', 'sys_user_sex',        '0', 'admin', sysdate(), '', null, '用户性别列表'),
(2,  '菜单状态', 'sys_show_hide',       '0', 'admin', sysdate(), '', null, '菜单状态列表'),
(3,  '系统开关', 'sys_normal_disable',  '0', 'admin', sysdate(), '', null, '系统开关列表'),
(4,  '任务状态', 'sys_job_status',      '0', 'admin', sysdate(), '', null, '任务状态列表'),
(5,  '任务分组', 'sys_job_group',       '0', 'admin', sysdate(), '', null, '任务分组列表'),
(6,  '系统是否', 'sys_yes_no',          '0', 'admin', sysdate(), '', null, '系统是否列表'),
(7,  '通知类型', 'sys_notice_type',     '0', 'admin', sysdate(), '', null, '通知类型列表'),
(8,  '通知状态', 'sys_notice_status',   '0', 'admin', sysdate(), '', null, '通知状态列表'),
(9,  '操作类型', 'sys_oper_type',       '0', 'admin', sysdate(), '', null, '操作类型列表'),
(10, '系统状态', 'sys_common_status',   '0', 'admin', sysdate(), '', null, '登录状态列表');

INSERT INTO sys_dict_data VALUES
(1,  1,  '男',       '0',       'sys_user_sex',        '',   '',        'Y', '0', 'admin', sysdate(), '', null, '性别男'),
(2,  2,  '女',       '1',       'sys_user_sex',        '',   '',        'N', '0', 'admin', sysdate(), '', null, '性别女'),
(3,  3,  '未知',     '2',       'sys_user_sex',        '',   '',        'N', '0', 'admin', sysdate(), '', null, '性别未知'),
(4,  1,  '显示',     '0',       'sys_show_hide',       '',   'primary', 'Y', '0', 'admin', sysdate(), '', null, '显示菜单'),
(5,  2,  '隐藏',     '1',       'sys_show_hide',       '',   'danger',  'N', '0', 'admin', sysdate(), '', null, '隐藏菜单'),
(6,  1,  '正常',     '0',       'sys_normal_disable',  '',   'primary', 'Y', '0', 'admin', sysdate(), '', null, '正常状态'),
(7,  2,  '停用',     '1',       'sys_normal_disable',  '',   'danger',  'N', '0', 'admin', sysdate(), '', null, '停用状态'),
(8,  1,  '正常',     '0',       'sys_job_status',      '',   'primary', 'Y', '0', 'admin', sysdate(), '', null, '正常状态'),
(9,  2,  '暂停',     '1',       'sys_job_status',      '',   'danger',  'N', '0', 'admin', sysdate(), '', null, '停用状态'),
(10, 1,  '默认',     'DEFAULT', 'sys_job_group',       '',   '',        'Y', '0', 'admin', sysdate(), '', null, '默认分组'),
(11, 2,  '系统',     'SYSTEM',  'sys_job_group',       '',   '',        'N', '0', 'admin', sysdate(), '', null, '系统分组'),
(12, 1,  '是',       'Y',       'sys_yes_no',          '',   'primary', 'Y', '0', 'admin', sysdate(), '', null, '系统默认是'),
(13, 2,  '否',       'N',       'sys_yes_no',          '',   'danger',  'N', '0', 'admin', sysdate(), '', null, '系统默认否'),
(14, 1,  '通知',     '1',       'sys_notice_type',     '',   'warning', 'Y', '0', 'admin', sysdate(), '', null, '通知'),
(15, 2,  '公告',     '2',       'sys_notice_type',     '',   'success', 'N', '0', 'admin', sysdate(), '', null, '公告'),
(16, 1,  '正常',     '0',       'sys_notice_status',   '',   'primary', 'Y', '0', 'admin', sysdate(), '', null, '正常状态'),
(17, 2,  '关闭',     '1',       'sys_notice_status',   '',   'danger',  'N', '0', 'admin', sysdate(), '', null, '关闭状态'),
(18, 99, '其他',     '0',       'sys_oper_type',       '',   'info',    'N', '0', 'admin', sysdate(), '', null, '其他操作'),
(19, 1,  '新增',     '1',       'sys_oper_type',       '',   'info',    'N', '0', 'admin', sysdate(), '', null, '新增操作'),
(20, 2,  '修改',     '2',       'sys_oper_type',       '',   'info',    'N', '0', 'admin', sysdate(), '', null, '修改操作'),
(21, 3,  '删除',     '3',       'sys_oper_type',       '',   'danger',  'N', '0', 'admin', sysdate(), '', null, '删除操作'),
(22, 4,  '授权',     '4',       'sys_oper_type',       '',   'primary', 'N', '0', 'admin', sysdate(), '', null, '授权操作'),
(23, 5,  '导出',     '5',       'sys_oper_type',       '',   'warning', 'N', '0', 'admin', sysdate(), '', null, '导出操作'),
(24, 6,  '导入',     '6',       'sys_oper_type',       '',   'warning', 'N', '0', 'admin', sysdate(), '', null, '导入操作'),
(25, 7,  '强退',     '7',       'sys_oper_type',       '',   'danger',  'N', '0', 'admin', sysdate(), '', null, '强退操作'),
(26, 8,  '生成代码', '8',       'sys_oper_type',       '',   'warning', 'N', '0', 'admin', sysdate(), '', null, '生成操作'),
(27, 9,  '清空数据', '9',       'sys_oper_type',       '',   'danger',  'N', '0', 'admin', sysdate(), '', null, '清空操作'),
(28, 1,  '成功',     '0',       'sys_common_status',   '',   'primary', 'N', '0', 'admin', sysdate(), '', null, '正常状态'),
(29, 2,  '失败',     '1',       'sys_common_status',   '',   'danger',  'N', '0', 'admin', sysdate(), '', null, '停用状态');


-- ---------------------------------------------------------------------------
-- Parameters (SysConfigServiceImpl.@PostConstruct caches these at boot)
-- ---------------------------------------------------------------------------
INSERT INTO sys_config VALUES
(1,  '主框架页-默认皮肤样式名称',     'sys.index.skinName',               'skin-blue',     'Y', 'admin', sysdate(), '', null, '蓝色 skin-blue、绿色 skin-green、紫色 skin-purple、红色 skin-red、黄色 skin-yellow'),
(2,  '用户管理-账号初始密码',         'sys.user.initPassword',            '123456',        'Y', 'admin', sysdate(), '', null, '初始化密码 123456'),
(3,  '主框架页-侧边栏主题',           'sys.index.sideTheme',              'theme-dark',    'Y', 'admin', sysdate(), '', null, '深黑主题theme-dark，浅色主题theme-light，深蓝主题theme-blue'),
(4,  '账号自助-是否开启用户注册功能', 'sys.account.registerUser',         'false',         'Y', 'admin', sysdate(), '', null, '是否开启注册用户功能（true开启，false关闭）'),
(5,  '用户管理-密码字符范围',         'sys.account.chrtype',              '0',             'Y', 'admin', sysdate(), '', null, '默认任意字符范围，0任意（密码可以输入任意字符），1数字（密码只能为0-9数字），2英文字母（密码只能为a-z和A-Z字母），3字母和数字（密码必须包含字母，数字）,4字母数字和特殊字符（目前支持的特殊字符包括：~!@#$%^&*()-=_+）'),
(6,  '用户管理-初始密码修改策略',     'sys.account.initPasswordModify',   '0',             'Y', 'admin', sysdate(), '', null, '0：初始密码修改策略关闭，没有任何提示，1：提醒用户，如果未修改初始密码，则在登录时就会提醒修改密码对话框'),
(7,  '用户管理-账号密码更新周期',     'sys.account.passwordValidateDays', '0',             'Y', 'admin', sysdate(), '', null, '密码更新周期（填写数字，数据初始化值为0不限制，若修改必须为大于0小于365的正整数），如果超过这个周期登录系统时，则在登录时就会提醒修改密码对话框'),
(8,  '主框架页-菜单导航显示风格',     'sys.index.menuStyle',              'default',       'Y', 'admin', sysdate(), '', null, '菜单导航显示风格（default为左侧导航菜单，topnav为顶部导航菜单）'),
(9,  '主框架页-是否开启页脚',         'sys.index.footer',                 'true',          'Y', 'admin', sysdate(), '', null, '是否开启底部页脚显示（true显示，false隐藏）'),
(10, '主框架页-是否开启页签',         'sys.index.tagsView',               'true',          'Y', 'admin', sysdate(), '', null, '是否开启菜单多页签显示（true显示，false隐藏）'),
(11, '用户登录-黑名单列表',           'sys.login.blackIPList',            '',              'Y', 'admin', sysdate(), '', null, '设置登录IP黑名单限制，多个匹配项以;分隔，支持匹配（*通配、网段）');

-- ---------------------------------------------------------------------------
-- Quartz jobs: status=1 (paused) so nothing fires during a scan.
-- 4.7.8 uses Spring Boot's in-memory Quartz store; QRTZ_* tables are NOT used.
-- ---------------------------------------------------------------------------
INSERT INTO sys_job VALUES
(1, '系统默认（无参）', 'DEFAULT', 'ryTask.ryNoParams',        '0/10 * * * * ?', '3', '1', '1', 'admin', sysdate(), '', null, ''),
(2, '系统默认（有参）', 'DEFAULT', 'ryTask.ryParams(\'ry\')',  '0/15 * * * * ?', '3', '1', '1', 'admin', sysdate(), '', null, ''),
(3, '系统默认（多参）', 'DEFAULT', 'ryTask.ryMultipleParams(\'ry\', true, 2000L, 316.50D, 100)',  '0/20 * * * * ?', '3', '1', '1', 'admin', sysdate(), '', null, '');

-- ---------------------------------------------------------------------------
-- Notices / code-generation demo row
-- ---------------------------------------------------------------------------
INSERT INTO sys_notice VALUES
('1', '温馨提醒：2018-07-01 若依新版本发布啦', '2', '新版本内容', '0', 'admin', sysdate(), '', null, '管理员'),
('2', '维护通知：2018-07-01 若依系统凌晨维护', '1', '维护内容',   '0', 'admin', sysdate(), '', null, '管理员');

INSERT INTO gen_table
  (table_id, table_name, table_comment, class_name, tpl_category, package_name, module_name, business_name, function_name, function_author, gen_type, gen_path, create_by, create_time)
VALUES
  (1, 'sys_user', '用户信息表', 'SysUser', 'crud', 'com.ruoyi.system', 'system', 'user', '用户', 'ruoyi', '0', '/', 'admin', NOW());

INSERT INTO gen_table_column
  (column_id, table_id, column_name, column_comment, column_type, java_type, java_field, is_pk, is_increment, is_required, is_insert, is_edit, is_list, is_query, query_type, html_type, dict_type, sort, create_by, create_time)
VALUES
  (1, 1, 'user_id',    '用户ID',   'bigint(20)',  'Long',   'userId',    '1', '1', '0', '1', '0', '1', '0', 'EQ',   'input', '', 1, 'admin', NOW()),
  (2, 1, 'login_name', '登录账号', 'varchar(30)', 'String', 'loginName', '0', '0', '1', '1', '1', '1', '1', 'LIKE', 'input', '', 2, 'admin', NOW());
