from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
from kivy.uix.checkbox import CheckBox
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.metrics import dp

import os
import yara


class ScannerApp(App):

    def build(self):
        Window.softinput_mode = 'below_target'
        root = BoxLayout(orientation='vertical', padding=dp(8), spacing=dp(8))

        self.status = Label(
            text='初始化...',
            size_hint_y=None, height=dp(36),
            halign='left', color=(0.7, 0.7, 0.7, 1)
        )
        self.status.bind(texture_size=self.status.setter('size'))
        root.add_widget(self.status)

        self.path_input = TextInput(
            text='/sdcard/',
            size_hint_y=None, height=dp(48), font_size=dp(14)
        )
        root.add_widget(self.path_input)

        quick = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(6))
        for label, path in [('SD卡', '/sdcard/'), ('下载', '/sdcard/Download/'),
                            ('文档', '/sdcard/Documents/'), ('临时', '/data/local/tmp/')]:
            b = Button(text=label, font_size=dp(13))
            b.bind(on_press=lambda inst, p=path: self.set_path(p))
            quick.add_widget(b)
        root.add_widget(quick)

        opts = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(10))
        opts.add_widget(Label(text='递归扫描', size_hint_x=None, width=dp(90), font_size=dp(13)))
        self.recurse = CheckBox(active=True, size_hint_x=None, width=dp(40))
        opts.add_widget(self.recurse)
        root.add_widget(opts)

        self.btn = Button(text='开始扫描', size_hint_y=None, height=dp(56), font_size=dp(18))
        self.btn.bind(on_press=self.on_scan)
        root.add_widget(self.btn)

        self.result = Label(
            text='等待扫描...',
            size_hint_y=None, halign='left', valign='top', font_size=dp(12)
        )
        self.result.bind(texture_size=self.result.setter('size'))
        scroll = ScrollView()
        scroll.add_widget(self.result)
        root.add_widget(scroll)

        Clock.schedule_once(self.load_rules, 0.5)
        return root

    def set_path(self, p):
        self.path_input.text = p

    def load_rules(self, dt):
        try:
            self.rules = yara.compile(filepath='rules.yar')
            self.status.text = 'YARA 规则已加载'
            self.result.text = '规则就绪，选择目录后点击扫描'
        except Exception as e:
            self.rules = None
            self.status.text = '规则加载失败'
            self.result.text = '错误: %s' % str(e)

    def on_scan(self, inst):
        if self.rules is None:
            self.result.text = '规则未加载，无法扫描'
            return
        self.btn.disabled = True
        self.btn.text = '扫描中...'
        Clock.schedule_once(lambda dt: self.do_scan(), 0.1)

    def do_scan(self):
        path = self.path_input.text.strip()
        if not os.path.exists(path):
            self.result.text = '路径不存在: %s' % path
            self.finish_btn()
            return

        out = ['目标: %s' % path, '']
        files = []

        if os.path.isfile(path):
            files.append(path)
        elif self.recurse.active:
            for root, dirs, names in os.walk(path):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for n in names:
                    files.append(os.path.join(root, n))
        else:
            for n in os.listdir(path):
                fp = os.path.join(path, n)
                if os.path.isfile(fp):
                    files.append(fp)

        out.append('待扫描: %d 个文件' % len(files))
        out.append('')

        hits = 0
        scanned = 0
        errors = 0

        for i, fp in enumerate(files):
            try:
                if os.path.getsize(fp) > 100 * 1024 * 1024:
                    continue
            except Exception:
                errors += 1
                continue

            scanned += 1
            try:
                matches = self.rules.match(fp)
                for m in matches:
                    hits += 1
                    out.append('命中: %s' % m.rule)
                    out.append('  %s' % fp)
                    out.append('')
            except Exception:
                errors += 1

            if i % 100 == 0:
                self.result.text = '扫描中... %d/%d  发现 %d' % (i, len(files), hits)

        out.append('=== 完成 ===')
        out.append('扫描: %d 个文件' % scanned)
        out.append('威胁: %d 个' % hits)
        out.append('错误: %d 个' % errors)

        self.result.text = '\n'.join(out)
        self.status.text = '完成: %d 文件, %d 威胁' % (scanned, hits)
        self.finish_btn()

    def finish_btn(self):
        self.btn.disabled = False
        self.btn.text = '开始扫描'


if __name__ == '__main__':
    ScannerApp().run()

