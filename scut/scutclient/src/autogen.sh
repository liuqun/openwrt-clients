#!/bin/sh
echo "Github下载的最新源代码需经过转换后方可正式发布"
echo "开始自动打包源码……"

echo "1、调用automake和autoconf等标准工具"
autoreconf --install
if test $? != 0 ; then
  echo "Automake或Autoconf出现错误，请检查错误提示信息"
  exit 1
fi

echo "2、调用./configure脚本自动完成各项检查"
./configure
if test $? != 0 ; then
  echo "缺少开发库，请参考README文档安装所需开发工具"
  exit 2
fi

echo "3、创建以下tar.gz源码包："
make dist --quiet
if test $? != 0 ; then
  echo "未能成功创建源码包，请检查错误提示信息"
  exit 3
fi
ls *.tar.gz

